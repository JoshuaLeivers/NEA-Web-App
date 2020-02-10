import configparser
import hashlib
import os
import secrets
import time
from datetime import timedelta
from urllib.parse import urlparse
import requests
import validators
from flask import Flask, request, make_response, render_template, redirect, url_for, abort, flash, send_from_directory
import mysql.connector
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from mysql.connector import errorcode
from socket import inet_aton, inet_ntoa
from flask_bcrypt import Bcrypt
import onetimepass
import base64
from wtforms import StringField, PasswordField, SubmitField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo, NoneOf, InputRequired


class Error(Exception):
    """Base class for exceptions in this app."""

    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)

    def __repr__(self):
        return self.message

    __str__ = __repr__


class ConfigSectionError(Error):
    """Exception raised when configparser cannot find a given section.

    Attributes:
        section -- section which configparser could not find
    """

    def __init__(self, section):
        Error.__init__(self, section + " section in config does not exist. Please configure "
                       + section + ". Resetting to defaults.")
        self.section = section
        self.args = (section,)


class ConfigOptionError(Error):
    """Exception raised when configparser cannot find a given option.

    Attributes:
        option -- option which configparser cannot find
        section -- section which the option should be in
    """

    def __init__(self, option, section):
        Error.__init__(self,
                       option + " missing from " + section + " section. Please configure " + section + "settings. "
                                                                                                       "Resetting to "
                                                                                                       "default.")
        self.option = option
        self.section = section
        self.args = (option, section)


class ConfigInvalidValueError(Error):
    """Exception raised when a config value is invalid.

    Attributes:
        key -- the config key whose value is invalid
    """

    def __init__(self, options, section):
        Error.__init__(self, ", ".join(
            options) + " invalid for the " + section + " section of the config.ini. Reconfigure to continue operating the web app.")
        self.options = options
        self.section = section
        self.args = (options, section)


defaults = {
    "Database": {
        "Domain": "127.0.0.1",
        "Port": "3306",
        "Username": "root",
        "Password": "",
        "Database": "portal"
    },
    "Email": {
        "Domain": "127.0.0.1",
        "Port": "587",
        "Username": "",
        "Password": "",
        "TLS": "True",
        "SSL": "False",
        "Default Sender": "joshua@leivers.dev",
        "Accounts Sender": "joshua@leivers.dev"
    },
    "Limits": {
        "User Requests": 5,
        "IP Requests": 20,
        "User Sessions": 7,
        "IP Sessions": 30,
        "Exempt Users": "",
        "Exempt IPs": "77.111.227.3 81.97.245.234"
    }
}

config = configparser.ConfigParser()
config.read("config.ini")

try:
    db = {
        "domain": config.get("Database", "Domain"),
        "port": config.get("Database", "Port"),
        "username": config.get("Database", "Username"),
        "password": config.get("Database", "Password"),
        "database": config.get("Database", "Database")
    }
except configparser.NoSectionError:
    config["Database"] = defaults["Database"]
    with open("config.ini", "w") as configfile:
        config.write(configfile)

    raise ConfigSectionError("Database")
except configparser.NoOptionError as err:
    config["Database"][err.option] = defaults["Database"][err.option]
    with open("config.ini", "w") as configfile:
        config.write(configfile)

    raise ConfigOptionError(err.option, "Database")

options = []
if db["domain"] is None or not (validators.domain(db["domain"]) or validators.ipv4(db["domain"])):
    options.append("Domain")
if db["port"] is None:
    options.append("Port")
if db["username"] is None:
    options.append("Username")
if db["database"] is None or db["database"] in ["mysql", "information_schema", "performance_schema"]:
    options.append("Database")

if len(options) > 0:
    raise ConfigInvalidValueError(options, "database")

try:
    email = {
        "domain": config.get("Email", "Domain"),
        "port": config.get("Email", "Port"),
        "username": config.get("Email", "Username"),
        "password": config.get("Email", "Password"),
        "tls": config.getboolean("Email", "TLS"),
        "ssl": config.getboolean("Email", "SSL"),
        "senders": {
            "default": config.get("Email", "Default Sender"),
            "accounts": config.get("Email", "Accounts Sender") or config.get("Email", "Default Sender")
        }
    }
except configparser.NoSectionError:
    config["Email"] = defaults["Email"]
    with open("config.ini", "w") as configfile:
        config.write(configfile)

    raise ConfigSectionError("Email")
except configparser.NoOptionError as err:
    config["Email"][err.option] = defaults["Email"][err.option]
    with open("config.ini", "w") as configfile:
        config.write(configfile)

    raise ConfigOptionError(err.option, "Email")

if email["domain"] is None or not (validators.domain(email["domain"]) or validators.ipv4(email["domain"])):
    options.append("Domain")
if email["port"] is None:
    options.append("Port")
if email["username"] is None:
    options.append("Username")
if email["senders"]["default"] is None or not validators.email(email["senders"]["default"]):
    options.append("Default Sender")

if len(options) > 0:
    raise ConfigInvalidValueError(options, "email")

try:
    limits = {
        "requests": {
            "user": config.getint("Limits", "User Requests"),
            "ip": config.getint("Limits", "IP Requests")
        },
        "sessions": {
            "user": config.getint("Limits", "User Sessions"),
            "ip": config.getint("Limits", "IP Sessions")
        },
        "exemptions": {
            "users": config.get("Limits", "Exempt Users").split(),
            # By default, split() separates a string by whitespace
            "ips": config.get("Limits", "Exempt IPs").split()
        }
    }
except configparser.NoSectionError:
    config["Limits"] = defaults["Limits"]
    with open("config.ini", "w") as configfile:
        config.write(configfile)

    raise ConfigSectionError("Limits")

if limits["requests"]["user"] is None:
    options.append("User Requests")
if limits["requests"]["ip"] is None:
    options.append("IP Requests")
if limits["sessions"]["user"] is None:
    options.append("User Sessions")
if limits["sessions"]["ip"] is None:
    options.append("IP Sessions")
if any(not validators.ipv4(ip) for ip in limits["exemptions"]["ips"]):
    options.append("Exempt IPs")

if len(options) > 0:
    raise ConfigInvalidValueError(options, "requests")


# Class used to be able to test if when a user is logged out it is because of a ban, and to store the bans for use
class Bans:
    def __init__(self, bans):
        self.bans = bans


# WTForms Templates
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    token = StringField("Token")
    submit = SubmitField("Sign In")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(1, 64, message="Username must be between "
                                                                                          "1-64 characters in "
                                                                                          "length.")])
    submit = SubmitField("Register")


class RegisterConfirmForm(FlaskForm):
    req_id = HiddenField("Request", validators=[DataRequired(), Length(64, 64)])
    password = PasswordField("Password", validators=[DataRequired(), Length(10, 72, message="Passwords must be "
                                                                                            "between 10 and 72 "
                                                                                            "characters long.")])
    password_confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    tfa = BooleanField("Setup Two Factor Authentication?", default=True)
    submit = SubmitField("Confirm")


class RegisterConfirmCodeForm(FlaskForm):
    req_id = StringField("Code", validators=[DataRequired(), Length(64, 64)])
    submit = SubmitField("Confirm")


class RegisterTFAForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField("Verify")


app = Flask(__name__)
app.config["SECRET_KEY"] = b'\xd91Oi~i\xcc\xdb5\xffWT\xea\xa2\xf6\xeb'  # Generated by os.urandom(16)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

app.config["MAIL_SERVER"] = email["domain"]
app.config["MAIL_PORT"] = email["port"]
app.config["MAIL_USE_TLS"] = email["tls"]
app.config["MAIL_USE_SSL"] = email["ssl"]
app.config["MAIL_USERNAME"] = email["username"]
app.config["MAIL_PASSWORD"] = email["password"]
app.config["MAIL_DEFAULT_SENDER"] = email["senders"]["default"]

mail = Mail(app)

try:
    cnx = mysql.connector.connect(user=db.get("username"), password=db.get("password"), host=db.get("domain"),
                                  port=db.get("port"), database=db.get("database"), autocommit=True)
except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("ERROR: The username or password for the database is incorrect. [" + err.errno + "]")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        print(
            "ERROR: Database does not exist. Please run database setup script [setup.py] or change database name in "
            "web app config. [" + str(err.errno) + "]")
    else:
        print(err)

    raise SystemExit("Web app was unable to connect to database and had to quit. Please check configuration and try "
                     "again.")
else:
    cursor = cnx.cursor()


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico",
                               mimetype="image/vnd.microsoft.icon")


@app.route("/")
@app.route("/dashboard")
def dashboard():
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            return redirect("logout", 303)
    else:
        if get_user_type() == 0:
            return render_template("dashboard_student.html")
        elif get_user_type() == 1:
            return render_template("dashboard_staff.html")


@app.route("/signin", methods=["GET"])
@app.route("/login", methods=["GET", "POST"])
def login():
    origin = get_redirect("login")
    logout = check_logout()
    if not logout:
        return redirect(origin, 303)
    elif isinstance(logout, Bans):
        return banned(logout)
    else:
        form = LoginForm()
        if form.validate_on_submit():
            cursor.execute("SELECT `password`, `2fa` FROM `users` WHERE `username` = %s", [form.username.data])
            user = cursor.fetchone()
            if user is not None:  # If there is a user by the given username
                hashed, secret = [user[i] for i in range(2)]

                if hashed is None:  # If there is no password set for the user
                    return redirect(url_for("reset") + "?user=" + form.username.data, code=303)
                elif not bcrypt.check_password_hash(hashed, form.password.data):  # If the password is not correct
                    flash("Username or password is incorrect.")
                    resp = make_response(render_template("login.html", form=form))
                    resp.delete_cookie("sessionID")
                    return resp, 403
                else:
                    if not secret:
                        return start_session(form.username.data, origin)
                    else:
                        if onetimepass.valid_totp(form.token.data, secret):
                            return start_session(form.username.data, origin)
            else:
                flash("Username or password is incorrect.")
                resp = make_response(render_template("login.html", form=form))
                resp.delete_cookie("sessionID")
                return resp, 403
        else:
            if request.args.get("username") is not None:
                form.username.data = request.args.get("username")
            resp = make_response(render_template("login.html", title="Sign In", form=form))
            resp.delete_cookie("sessionID")
            return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    logout = check_logout()
    if not logout:
        return redirect(get_redirect("register"), 303)
    elif isinstance(logout, Bans):
        return banned(logout)
    else:
        form = RegisterForm()
        if form.validate_on_submit():
            cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED(); CALL REQUESTS_REMOVEOLD();", multi=True)

            username = form.username.data
            cursor.execute("SELECT TRUE FROM `users` WHERE `username` = %s", (username,))
            if not cursor.fetchall():
                cursor.execute("SELECT TRUE FROM `requests` WHERE `req_ip` = %s", (get_ip(),))
                if len(cursor.fetchall()) >= limits["requests"]["ip"]:
                    flash("Too many registration requests have been made from this IP. Please try again later.")
                    return render_template("register.html", title="Register", form=form), 429
                else:
                    cursor.execute("SELECT TRUE FROM `requests` WHERE `req_username` = %s", (username,))
                    if len(cursor.fetchall()) >= limits["requests"]["user"]:
                        flash(
                            "Too many registration requests have been made for this username. Please try again later.")
                        return render_template("register.html", title="Register", form=form), 429
                    else:
                        req_id = secrets.token_urlsafe(48)  # As this is Base64 encoded, this is 64 characters long
                        cursor.execute("SELECT TRUE FROM `requests` WHERE `req_id` = %s", (req_id,))
                        while cursor.fetchone():
                            req_id = secrets.token_urlsafe(48)
                            cursor.execute("SELECT TRUE FROM `requests` WHERE `req_id` = %s", (req_id,))

                        url = url_for("register_confirm") + "?id=" + req_id

                        msg = Message("Confirm Student Portal Account", recipients=[username + "@gmail.com"],
                                      # TODO: Change to nuast.org when complete
                                      sender=("Student Portal", "joshua@leivers.dev"))
                        msg.html = "<h2>Confirm your student portal account</h2>" + \
                                   "<p>Never share this email or the links it contains! Anybody with your " + \
                                   "confirmation link can create and access an account in your name!</p>" + \
                                   "<p>You recently requested an account for the NUAST student portal. " + \
                                   "To confirm your account, click <a href='" + url + "'>here</a>.</p>" + \
                                   "<p>Can't click the link? Copy and paste the following URL into your browser:</p>" + \
                                   "<p><a href='" + url + "'>" + url + "</a></p>" + \
                                   "<p>Didn't request this? Don't worry. You can just ignore this email, or use the " + \
                                   "link yourself anyway. Nobody will be able to access your account unless they " + \
                                   "themselves use this link, so make sure to keep it private!</p>" + \
                                   "<h4>Who requested this?</h4>" + \
                                   "<p><b>IP</b>: " + request.remote_addr + str((request.remote_addr in
                                                                                 limits["exemptions"][
                                                                                     "ips"]) and "NUAST") \
                                   + "</p>" + \
                                   "<p><b>Browser</b>: " + request.user_agent.browser + " " + \
                                   request.user_agent.version + \
                                   "</p>" + \
                                   "<p><b>Operating System</b>: " + request.user_agent.platform + "</p>"
                        mail.send(msg)

                        cursor.execute("INSERT INTO `requests` (`req_id`, `req_username`, `req_time`, `req_useragent`, "
                                       "`req_ip`) VALUES (%s, %s, %s, %s, %s)", (req_id, username, time.strftime(
                            "%Y-%m-%d %H:%M:%S"), get_useragent(), get_ip()))

                        return make_response(render_template("registered.html", title="Registered", username=username,
                                                             redirect=url_for("register_confirm_code")))
            else:
                flash("A user already exists using the given username.")
                return render_template("register.html", title="Register", form=form), 403
        else:
            return render_template("register.html", title="Register", form=form)


@app.route("/register/confirm", methods=["GET", "POST"])
def register_confirm():
    logout = check_logout()
    if not logout:
        return redirect(get_redirect("register_confirm"), 303)
    elif isinstance(logout, Bans):
        return banned(logout)
    else:
        form = RegisterConfirmForm()
        if form.validate_on_submit():
            cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED(); CALL REQUESTS_REMOVEOLD();", multi=True)

            cursor.execute("SELECT `req_username`, `req_time` FROM `requests` WHERE `req_id` = %s", (form.req_id.data,))
            data = cursor.fetchone()
            if not data:
                flash("Account creation request expired or invalid.")
                return redirect("register", 303)
            else:
                username = data[0]
                cursor.execute("SELECT TRUE FROM `users` WHERE `username` = %s", (username,))
                if cursor.fetchone():
                    flash("The account '" + username + "' already exists.")
                    return redirect(url_for("login") + "?username=" + username, 303)
                else:
                    password = form.password.data
                    invalid = check_password_invalid(password)
                    if invalid:
                        flash(invalid)
                        expires = data[1] + timedelta(minutes=30)
                        return render_template("register_confirm.html", title="Confirm Registration", username=username,
                                               expires=expires, form=form), 422
                    else:
                        cursor.execute("INSERT INTO `users` (`username`, `password`) VALUES (%s, %s)",
                                       (username, bcrypt.generate_password_hash(password)))
                        return start_session(username, "register_confirm",
                                             (form.tfa.data and url_for("settings_tfa") or url_for("dashboard")))
        elif request.method == "GET":
            if request.args.get("id") is not None:
                cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED(); CALL REQUESTS_REMOVEOLD();", multi=True)

                cursor.execute("SELECT `req_username`, `req_time` FROM `requests` WHERE `req_id` = %s",
                               (request.args.get("id"),))
                data = cursor.fetchone()
                if data is None:
                    flash("Account creation request expired or invalid.")
                    return redirect(url_for("register"), 303)
                else:
                    form.req_id.data = request.args.get("id")
                    username = data[0]
                    expires = data[1] + timedelta(minutes=30)
                    return render_template("register_confirm.html", title="Confirm Registration", username=username,
                                           expires=expires, form=form)
            else:
                return redirect(url_for("register_confirm_code")), 303
        else:
            return redirect(url_for("register_confirm_code")), 303


@app.route("/register/confirm/code", methods=["GET", "POST"])
def register_confirm_code():
    logout = check_logout()
    if not logout:
        return redirect(get_redirect("register_confirm_code"))
    elif isinstance(logout, Bans):
        return banned(logout)
    else:
        form = RegisterConfirmCodeForm()
        if form.validate_on_submit():
            cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED(); CALL REQUESTS_REMOVEOLD();", multi=True)

            cursor.execute("SELECT TRUE FROM `requests` WHERE `req_id` = %s", (form.req_id.data,))
            if cursor.fetchone():
                return redirect(url_for("register_confirm") + "?id=" + form.req_id.data)
            else:
                flash("Account creation request expired or invalid.")
                return render_template("register_confirm_code.html", form=form)
        else:
            return render_template("register_confirm_code.html", form=form)


@app.route("/logout")
def logout():
    resp = make_response(redirect("login", 303))
    resp.delete_cookie("sessionID")
    resp.headers.set("Referer", request.referrer)
    return resp


def banned(bans):
    bans = bans.bans
    if any(ban["visible"] == 0 for ban in bans.bans):
        abort(500)
    else:
        baninfo = ""
        for ban in bans.bans:
            if ban["visible"] < 5:
                if ban["visible"] < 4:
                    ban["admin"] = None
                    if ban["visible"] < 3:
                        ban["reason"] = None
                        if ban["visible"] < 2:
                            ban["start"] = None

            baninfo = ban
            if not any(ban["visible"] == 51 for ban in bans.bans):
                if baninfo["username"] is None:
                    break
                elif baninfo["ip"] is None and not any(banned["username"] is None for banned in bans.bans):
                    break
                elif not any(banned["ip"] is None or banned["username"] is None for banned in bans.bans):
                    break
            else:
                if baninfo["visible"] == 51:
                    break

        if baninfo["visible"] == 51:
            return make_response(render_template("err_banned_legal.html", ban=baninfo), 451)
        else:
            return make_response(render_template("err_banned.html", ban=baninfo), 403)


# Error Handling
@app.errorhandler(451)
def err_legal():
    return render_template("err_451.html"), 451


# Value Injection
@app.context_processor
def inject_emails():
    return dict(email_accounts=email["senders"]["accounts"], email_default=email["senders"]["default"])


# Utility functions
def get_ip():
    return int.from_bytes(inet_aton(request.remote_addr), "big")


def get_useragent(full=False):
    if not full:
        return str(request.user_agent)[:256]
    else:
        return str(request.user_agent)


def get_user_type():
    cursor.execute("SELECT `u`.`type` FROM `users` `u` INNER JOIN `sessions` `s` WHERE `s`.`sess_id` = %s",
                   (request.cookies.get("sessionID"),))
    return cursor.fetchone()[0]


def check_password_pwned(password):
    password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    req = requests.get("https://api.pwnedpasswords.com/range/" + password[:5])
    if req.status_code == 200:
        if password[5:] in req.text:
            return True
        else:
            return False
    else:
        print("WARNING: Unable to contact https://api.pwnedpasswords.com/")
        return False


def check_password_invalid(password):
    if not 9 < len(password) < 73:
        return "Passwords must be between 10 and 72 characters in length."
    elif check_password_pwned(password):
        return "Your password has been leaked in the past. If you have used this password elsewhere, change it " \
               "immediately to avoid your accounts being breached. "
    else:
        return False


def check_logout():
    cursor.execute("CALL BANS_REMOVEOLD(); CALL SESSIONS_REMOVEOLD(); CALL ETC_REMOVEBANNED();", multi=True)
    cookies = request.cookies
    if cookies.get("sessionID") is not None:
        cursor.execute("SELECT `username`, `sess_ip`, `sess_useragent` FROM `sessions` WHERE `sess_id` = %s",
                       (cookies.get("sessionID"),))
        session = cursor.fetchone()
        if session:
            bans = check_ban(get_ip(), session[0])
            if bans:
                cursor.execute("DELETE FROM sessions WHERE username=%s", session[0])
                return bans
            else:
                if session[1] != get_ip() or session[2] != get_useragent():
                    cursor.execute("DELETE FROM `sessions` WHERE `sess_id` = %s", (cookies.get("sessionID"),))
                    return "IP or system changed. Please log in again to confirm your identity."
                else:
                    return False
        else:
            return "Session timed out."
    else:
        return True


def check_ban(ip, username):
    cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED();", multi=True)

    cursor.execute("SELECT `username`, `ban_ip`, `staff`, `ban_visible`, `ban_reason`, `ban_start`, "
                   "`ban_end` FROM bans WHERE `ban_start` < NOW() AND `ban_end` > NOW() AND ((`ban_ip`=%s "
                   "AND `username`=%s) OR (`ban_ip` IS NULL and `username`=%s) OR (`ban_ip`=%s AND "
                   "`username` IS NULL))", (ip, username, username, ip))
    banlist = cursor.fetchall()

    if banlist is not None:
        bans = []
        for ban in banlist:
            ban = {
                "username": ban[0],
                "ip": ban[1],
                "admin": ban[2],
                "visible": ban[3],
                "reason": ban[4],
                "start": ban[5],
                "end": ban[6]
            }
            bans.append(ban)

        return bans
    else:
        return False


def start_session(username, origin, target=None):
    bans = check_ban(get_ip(), username)
    if bans:
        return banned(bans)
    else:
        cursor.execute("CALL SESSIONS_REMOVEOLD();")
        # These are the characters allowed within a cookie value
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%&'()*+-./:<=>?@[]^_`{|}~"
        sess_id = "".join(secrets.choice(chars) for i in range(32))

        cursor.execute("INSERT INTO sessions (sess_id, username, sess_start, sess_last, sess_ip, sess_useragent) VALUES"
                       "(%s, %s, NOW(), NOW(), %s, %s)", (sess_id, username, get_ip(), request.user_agent.string))

        if target is None:
            target = get_redirect(origin)
        resp = redirect(target, 303)
        resp.set_cookie("sessionID", sess_id, max_age=None, httponly=True)
        return resp


def get_redirect(this):
    origin = request.args.get("redirect")
    if origin:
        return url_for(origin)

    origin = request.referrer
    if urlparse(origin).hostname == request.url_root and origin != this:
        return origin

    return url_for("dashboard")


if __name__ == '__main__':
    app.run(ssl_context="adhoc", host="0.0.0.0")
