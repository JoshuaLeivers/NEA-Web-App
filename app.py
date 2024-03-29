import configparser
import hashlib
import os
import re
import secrets
import string
import time
import traceback
from datetime import timedelta, datetime
from operator import itemgetter
from urllib.parse import urlparse
import xlrd
import requests
import validators
from flask import Flask, request, make_response, render_template, redirect, url_for, abort, flash, send_from_directory
import mysql.connector
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect
from libgravatar import Gravatar
from mysql.connector import errorcode
from socket import inet_aton
from flask_bcrypt import Bcrypt
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.utils import escape
from forms import *
from errors import ConfigInvalidValueError, ConfigSectionError, ConfigOptionError, InvalidUser
from defaults import defaults

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
            "accounts": config.get("Email", "Accounts Sender") or config.get("Email", "Default Sender"),
            "webmaster": config.get("Email", "Webmaster Sender") or config.get("Email", "Default Sender")
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
            "users": config.get("Limits", "Exempt Users"),
            "ips": config.get("Limits", "Exempt IPs")
            # Exemptions are stored in the format '<Exemption (IP/Username)>:<Name>,<Exemption (IP/Username)>:<Name>',
            # where for IPs, 'Name' is the place that uses the IP (e.g. NUAST itself, or the University of Nottingham)
        }
    }
except configparser.NoSectionError:
    config["Limits"] = defaults["Limits"]
    with open("config.ini", "w") as configfile:
        config.write(configfile)

    raise ConfigSectionError("Limits")
except configparser.NoOptionError as err:
    config["Limits"][err.option] = defaults["Limits"][err.option]
    with open("config.ini", "w") as configfile:
        config.write(configfile)

        raise ConfigOptionError(err.option, "Limits")

try:
    limits["exemptions"]["users"] = dict((k.strip(), v.strip()) for k, v in
                                         (pair.split(":") for pair in limits["exemptions"]["users"].split(",")))
    limits["exemptions"]["ips"] = dict((k.strip(), v.strip()) for k, v in
                                       (pair.split(":") for pair in limits["exemptions"]["ips"].split(",")))
except ValueError as err:
    # This is raised if one of the exemptions strings does not fit the format required. If it is raised due to anything
    # else, the original error will be returned.
    if "users" in traceback.format_exc(2):
        raise ConfigInvalidValueError(["Exempt Users"], "Limits")
    elif "ips" in traceback.format_exc(2):
        raise ConfigInvalidValueError(["Exempt IPs"], "Limits")
    else:
        raise err

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


@app.route("/avatar/<username>")
def avatar(username):
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            return redirect(url_for("logout"), 303)
    else:
        if is_user(username):
            if get_username() == username or get_user_type() == 1:
                try:
                    resp = send_from_directory(os.path.join(app.root_path, "static/avatars"), username + ".png",
                                               mimetype="image/png")
                except NotFound:
                    resp = redirect(Gravatar(username + "@gmail.com").get_image(size=200, use_ssl=True), 302)

                return resp
            else:
                return error_handler(None, 403, "You cannot access other users' avatars.")
        else:
            raise InvalidUser


@app.route("/")
@app.route("/dashboard")
def dashboard():
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect("logout", 303)
    else:
        cursor.execute("CALL ANNOUNCEMENTS_REMOVEOLD()")
        cursor.execute("SELECT `anno_message`, `sender`, `anno_type` FROM `announcements` INNER JOIN `userannos` ON "
                       "`userannos`.`anno_id` = `announcements`.`anno_id` WHERE `userannos`.`username` = %s",
                       (get_username(),))
        annos = cursor.fetchall()
        if annos is not None:
            for anno in annos:
                flash("<b>" + anno[1] + "</b>: " + escape(anno[0]), category="announcement")
        if get_user_type() == 0:
            return render_template("dashboard_student.html", title="Dashboard")
        elif get_user_type() == 1:
            return render_template("dashboard_staff.html", title="Dashboard")


@app.route("/login", methods=["GET", "POST"])
def login():
    origin = get_redirect("login")
    logout = check_logout()
    if not logout:
        flash("You are already signed in.")
        return redirect(origin, 303)
    elif isinstance(logout, Bans):
        return banned(logout)
    else:
        form = LoginForm()
        if form.validate_on_submit():
            cursor.execute("SELECT `password` FROM `users` WHERE `username` = %s", (form.username.data,))
            user = cursor.fetchone()
            if user is not None:  # If there is a user by the given username
                hashed = user[0]

                if hashed is None:  # If there is no password set for the user
                    return redirect(url_for("reset") + "?user=" + form.username.data, code=303)
                elif not bcrypt.check_password_hash(hashed, form.password.data):  # If the password is not correct
                    flash("Username or password is incorrect.")
                    resp = make_response(render_template("login.html", title="Sign In", form=form))
                    resp.delete_cookie("sessionID")
                    return resp, 403
                else:
                    return start_session(form.username.data, origin)
            else:
                flash("Username or password is incorrect.")
                resp = make_response(render_template("login.html", form=form, title="Sign In"))
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
        flash("You are already signed in.")
        return redirect(get_redirect("register"), 303)
    elif isinstance(logout, Bans):
        return banned(logout)
    else:
        form = RegisterForm()
        if form.validate_on_submit():
            cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED(); CALL REQUESTS_REMOVEOLD();", multi=True)

            username = form.username.data.lower()
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

                        msg = Message("Confirm Student Portal Account", recipients=[username + "@nuast.org"],
                                      sender=("Student Portal", email["senders"]["accounts"]))
                        msg.html = f"""<h1>Confirm your student portal account</h1>
                        <p>Never share or forward this email or the links it contains! 
                        Anybody with your confirmation link or code can create and access an account in your name!</p>
                        <p>You recently requested an account for the NUAST student portal. 
                        To confirm your account, click <a href="{url}">here</a>.</p>
                        <p>Can't use the link? Copy the following code into the box on 
                        <a href="{url_for("register_confirm_code")}">{url_for("register_confirm_code")}</a>:</p>
                        <p>{req_id}</p>
                        <p>Didn't request this? Don't worry. You can just ignore this email, or use the link yourself 
                        anyway. Nobody can access your account without the links or code in this email, 
                        or your password once you have created your account.</p> 
                        <h3>Who requested this?</h3>
                        <p><b>IP</b>: {request.remote_addr} <b>
                        {limits["exemptions"]["ips"].get(request.remote_addr) or ''}</b></p> 
                        <p><b>Browser</b>: {request.user_agent.browser} {request.user_agent.version}</p>"""

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
        flash("You are already signed in.")
        return redirect(get_redirect("register_confirm"), 303)
    elif isinstance(logout, Bans):
        return banned(logout)
    else:
        form = RegisterConfirmForm()
        if request.method == "POST":
            if form.validate_on_submit():
                cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED(); CALL REQUESTS_REMOVEOLD();", multi=True)

                cursor.execute("SELECT `req_username` FROM `requests` WHERE `req_id` = %s",
                               (form.req_id.data,))
                username = cursor.fetchone()
                if not username:
                    flash("Account creation request expired or invalid.")
                    return redirect(url_for("register"), 303)
                else:
                    username = username[0]
                    cursor.execute("SELECT TRUE FROM `users` WHERE `username` = %s", (username,))
                    if cursor.fetchone():
                        flash("The account '" + username + "' already exists.")
                        return redirect(url_for("login") + "?username=" + username, 303)
                    else:
                        password = form.password.data
                        invalid = check_password_invalid(password)
                        if invalid:
                            flash(invalid)
                            return render_template("register_confirm.html", title="Confirm Registration",
                                                   username=username, form=form), 422
                        else:
                            cursor.execute("INSERT INTO `users` (`username`, `password`) VALUES (%s, %s)",
                                           (username, bcrypt.generate_password_hash(password)))

                            if re.search("^(4004[a-z][a-z][a-z][a-z]\\d\\d)", username):
                                cursor.execute("UPDATE `users` SET `type` = 0, `year` = %s WHERE `username` = %s",
                                               (int(re.sub("[^0-9]", "", username)[4:6]) -
                                                int(datetime.now().strftime("%y")) + 7, username))
                            else:
                                cursor.execute("UPDATE `users` SET `type` = 1")

                            return start_session(username, "register_confirm", url_for("dashboard"))
            else:
                if form.req_id.errors is None:
                    cursor.execute("SELECT `req_username`, `req_time` FROM `requests` WHERE `req_id` = %s",
                                   (form.req_id.data,))
                    data = cursor.fetchone()
                    if data is not None:
                        return render_template("register_confirm.html", title="Confirm Registration", form=form,
                                               username=data[0], expires=data[1] + timedelta(minutes=30))
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


@app.route("/detentions/")
def detentions_own():
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    elif get_user_type() == 1:
        return redirect(url_for("search"), 303)
    else:
        return detentions(get_username())


@app.route("/detentions/<username>")
def detentions(username):
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    elif is_user(username):
        if get_username() == username or get_user_type() == 1:
            table = f"<h1>Homework</h1><p>{username}@nuast.org</p>"
            if get_user_type(username) == 0:
                cursor.execute("SELECT `det_start`, `teacher`, `det_length`, `det_room`, `det_info` FROM `detentions` "
                               "WHERE `student` = %s ORDER BY `det_start` DESC", (username,))

                detentions = cursor.fetchall()
                if detentions:
                    table += "<table><tr><th>Start</th><th>Teacher</th><th>Length</th><th>Room</th><th>Info</th></tr>"

                    for det in detentions:
                        table += f"""<tr><th>{det[0]}</th><th>{det[1]}</th><th>{det[2]}</th><th>{det[3]}</th>
<th>{det[4]}</th></tr>"""

                    table += "</table>"
                else:
                    table += "<h3>No detentions available.</h3>"
            else:
                cursor.execute("SELECT `det_start`, `student`, `det_length`, `det_room`, `det_info` FROM `detentions` "
                               "WHERE `teacher` = %s", (username,))

                detentions = cursor.fetchall()
                if detentions:
                    table += "<table><tr><th>Start</th><th>Student</th><th>Length</th><th>Room</th><th>Info</th></tr>"

                    for det in detentions:
                        table += f"""<tr><th>{det[0]}</th><th><a href="{url_for("profile", username=det[1])}">{det[1]}
</a></th><th>{det[2]}</th><th>{det[3]}</th><th>{det[4]}</th></tr>"""

                    table += "</table>"
                else:
                    table += "<h3>No detentions available.</h3>"

            return render_template("table.html", table=table)
        else:
            return error_handler(None, 403, "Students cannot view other users' detentions.")
    else:
        raise InvalidUser


@app.route("/passwordcriteria")
def password_criteria():
    return render_template("password_criteria.html")


@app.route("/register/confirm/code", methods=["GET", "POST"])
def register_confirm_code():
    logout = check_logout()
    if not logout:
        flash("You are already signed in.")
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


@app.route("/profile/")
def profile_own():
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    else:
        return profile(get_username())


@app.route("/profile/<username>")
def profile(username):
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    elif is_user(username):
        if get_username() == username or get_user_type(get_username()) == 1:
            data = get_userdata(username)
            name = get_name(username)

            if get_user_type(username) == 0:
                if data[1] is not None:
                    attendance = f"<b>Attendance</b>: {data[1]}"
                else:
                    attendance = ""

                if data[2] is not None:
                    year = f" - Year {data[2]}"
                else:
                    year = ""

                tutor = get_tutor(username)
                if tutor is not None:
                    tutor = f"<b>Tutor</b>: {tutor}"
                else:
                    tutor = ""

                return render_template("profile_student.html", profile_username=data[0], name=name,
                                       profile_attendance=attendance, profile_year=year, tutor=tutor)
            else:
                return render_template("profile_staff.html", profile_username=username, name=name)
        else:
            return error_handler(None, 403, "You cannot access other users' profiles.")
    else:
        raise InvalidUser


@app.route("/homework/")
def homework_own():
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    elif get_user_type(get_username()) == 1:
        return redirect(url_for("search"), 303)
    else:
        return homework(get_username())


@app.route("/homework/<username>")
def homework(username):
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    elif is_user(username):
        if get_username() == username or get_user_type() == 1:
            table = f"<h1>Homework</h1><p>{username}@nuast.org</p>"
            if get_user_type(username) == 0:
                cursor.execute("SELECT h.`hwk_desc`, h.`teacher`, h.`hwk_set`, h.`hwk_due`, h.`hwk_info` FROM "
                               "`homework` `h` INNER JOIN `hwkset` `s` ON `s`.`hwk_desc` = h.`hwk_desc` AND "
                               "`s`.`teacher` = h.`teacher` AND `s`.`hwk_due` = h.`hwk_due` WHERE `s`.`student` = %s OR"
                               " `s`.`class_id` IN (SELECT `class_id` FROM `userclasses` WHERE `username` = %s) ORDER "
                               "BY `h`.`hwk_due` DESC", (username, username))

                homework = cursor.fetchall()
                if homework:
                    table += "<table><tr><th>Description</th><th>Teacher</th><th>Set</th><th>Due</th><th>Info</th></tr>"

                    for hwk in homework:
                        table += f"""<tr><th>{hwk[0]}</th><th>{hwk[1]}</th><th>{hwk[2]}</th><th>{hwk[3]}</th>
<th>{hwk[4]}</th></tr>"""

                    table += "</table>"
                else:
                    table += "<h3>No homework available.</h3>"
            else:
                cursor.execute("SELECT h.`hwk_desc`, h.`hwk_set`, h.`hwk_due`, h.`hwk_info`, s.`class_id`, s.`student`"
                               " FROM `homework` `h` LEFT JOIN `hwkset` `s` ON `h`.`hwk_desc` = `s`.`hwk_desc` AND "
                               "`h`.`teacher` = `s`.`teacher` AND `h`.`hwk_due` = `s`.`hwk_due` WHERE "
                               "`h`.`teacher` = %s", (username,))

                homework = cursor.fetchall()
                if homework:
                    table += "<table><tr><th>Description</th><th>Set</th><th>Due</th><th>Info</th><th>Class/Student" \
                             "</th></tr>"

                    for hwk in homework:
                        table += f"<tr><th>{hwk[0]}</th><th>{hwk[1]}</th><th>{hwk[2]}</th><th>{hwk[3]}</th><th>"
                        if hwk[4] is None:
                            table += hwk[5]
                        else:
                            table += hwk[4]
                        table += "</th></tr>"

                    table += "</table>"
                else:
                    table += "<h3>No homework available.</h3>"

            return render_template("table.html", table=table)
        else:
            return error_handler(None, 403, "Students cannot view other users' homework.")
    else:
        raise InvalidUser


@app.route("/timetable/")
def timetable_own():
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    elif get_user_type() == 1:
        return redirect(url_for("search"), 303)
    else:
        return timetable(get_username())


@app.route("/timetable/<username>")
def timetable(username):
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"), 303)
    elif is_user(username):
        if get_username() == username or get_user_type(get_username()) == 1:
            if get_user_type(username) == 0:
                path = os.path.join(app.root_path, "static/timetables", username + ".xls")
                if os.path.isfile(path):
                    sheet = xlrd.open_workbook(path).sheet_by_index(0)

                    table = f"""<h1>Timetable</h1><p>{username}@nuast.org</p><table>
                    {"".join(("<tr>" + "".join(("<th>" + str(sheet.cell_value(y, x)) + "</th>") for x in range(sheet.ncols)) + "</tr>") for y in range(sheet.nrows))}
                    </table>"""

                    return render_template("table.html", table=table)
                else:
                    return error_handler(None, 503, "The timetable you are looking for has not been uploaded yet. "
                                                    "Please try again later.")
            else:
                return error_handler(None, 422, "Staff members do not have timetables available for viewing.")
        else:
            return error_handler(None, 403, "Students cannot view other users' timetables.")
    else:
        raise InvalidUser


@app.route("/search", methods=["GET", "POST"])
def search():
    logout = check_logout()
    if logout:
        if isinstance(logout, Bans):
            return banned(logout)
        else:
            flash(logout)
            return redirect(url_for("login"))
    elif get_user_type() == 0:
        return error_handler(None, 403, "Students cannot access other students' information.")
    else:
        form = SearchForm()
        cursor.execute("SELECT `class_id` FROM `classes`")
        form.class_id.choices = [("*", "Classes")]
        for c in cursor.fetchall():
            form.class_id.choices.append((c[0], c[0]))

        if form.validate_on_submit():
            print()
            if (form.surname.data or form.forename.data or form.username.data) == "" and form.class_id.data == "*":
                cursor.execute("SELECT `username`, `type` FROM `users`")
            else:
                statement = "SELECT `u`.`username`, `u`.`type` FROM `users` `u` "
                where = "WHERE"
                data = []
                if form.class_id.data != "*":
                    statement += "INNER JOIN `userclasses` `c` ON `c`.`username` = `u`.`username`"
                    where += " `c`.`class_id` = %s"
                    data.append(form.class_id.data)
                if form.forename.data != "":
                    if where != "WHERE":
                        where += " AND"
                    where += " `u`.`forename` LIKE CONCAT('%', %s, '%')"
                    data.append(form.forename.data)
                if form.surname.data != "":
                    if where != "WHERE":
                        where += " AND"
                    where += " `u`.`surname` LIKE CONCAT('%', %s, '%')"
                    data.append(form.surname.data)
                if form.username.data != "":
                    if where != "WHERE":
                        where += " AND"
                    where += " `u`.`username` LIKE CONCAT('%', %s, '%')"
                    data.append(form.username.data)

                cursor.execute(statement + where, tuple(data))

            users = cursor.fetchall()
            if users is None:
                flash("No users found.")
                students = ""
            else:
                students = "<h2>Results</h2><table>"
                for user in users:
                    students += f"<tr><th>{user[0]}"

                    if user[1] == 0:
                        students += f""" <a href='{url_for('timetable', username=user[0])}'><i class='fas fa-calendar
-times'></i></a> <a href="{url_for("detentions", username=user[0])}"><i class="fas fa-gavel"></i></a> <a href="{
                        url_for("homework", username=user[0])}"><i class="fas fa-clipboard-list"></i></a>"""

                    students += f" <a href='{url_for('profile', username=user[0])}><i class='fas fa-user'></i></a>"

                    students += "</th></tr>"

            return render_template("search.html", title="User Search", form=form, students=students)
        else:
            return render_template("search.html", title="User Search", form=form, students="")


@app.route("/logout")
def logout():
    resp = make_response(redirect("login", 303))
    resp.delete_cookie("sessionID")
    resp.headers.set("Referer", request.referrer)
    return resp


@app.route("/darkmode")
def darkmode():
    target = request.args.get("redirect")
    if target is None:
        target = request.referrer
    else:
        target = url_for(target)
    resp = make_response(redirect(target, 303))
    if not request.cookies.get("colours"):
        resp.set_cookie("colours", "dark")
    elif request.cookies.get("colours") == "dark":
        resp.set_cookie("colours", "light")
    else:
        resp.set_cookie("colours", "dark")

    return resp


def banned(bans):
    bans = bans.bans
    if any(ban["visible"] == 0 for ban in bans):
        abort(500)
    elif any(ban["visible"] == 51 for ban in bans):
        abort(451)
    else:
        ban = sorted(bans, key=itemgetter("visible"))[0]
        if ban["visible"] < 5:
            if ban["visible"] < 4:
                ban["admin"] = None
                if ban["visible"] < 3:
                    ban["reason"] = None
                    if ban["visible"] < 2:
                        ban["start"] = None

        return render_template("banned.html", ban=ban), 403


# Error Handling
@app.errorhandler(Exception)
def error_handler(error, code=None, description=None):
    if isinstance(error, HTTPException):
        code = code or error.code
        description = description or error.description
        return render_template("error.html", code=code, description=description), code
    else:
        abort(500)


# Registering Custom HTTP Exceptions
app.register_error_handler(InvalidUser, error_handler)


# Value Injection
@app.context_processor
def inject_emails():
    return dict(email_accounts=email["senders"]["accounts"], email_default=email["senders"]["default"],
                email_webmaster=email["senders"]["webmaster"])


@app.context_processor
def inject_userdata():
    data = get_userdata()
    if data is not None:
        return dict(username=data[0], forename=data[1], surname=data[2], attendance=data[3], year=data[4])
    else:
        return dict(dummy="")


# Utility functions
def has_permission(username, permission):
    cursor.execute("SELECT TRUE FROM `permissions` WHERE `username` = %s AND `perm_id` = %s", (username, permission))
    if cursor.fetchone() is None:
        return False
    else:
        return True


def is_user(username):
    cursor.execute("SELECT TRUE FROM `users` WHERE `username` = %s", (username,))
    if cursor.fetchone() is None:
        return False
    else:
        return True


def get_tutor(username=None):
    if username is None:
        username = get_username()

    cursor.execute("SELECT c.`class_id` FROM `userclasses` `c` INNER JOIN `users` `u` ON c.`username` = u.`username` "
                   "WHERE c.`username` = %s AND c.`class_id` REGEXP CONCAT(u.`year`, '\\.\\d')", (username,))
    data = cursor.fetchone()
    if data is None:
        return None
    else:
        return data[0]


def get_name(username=None):
    if username is None:
        username = get_username()

    cursor.execute("SELECT `forename`, `surname` FROM `users` WHERE `username` = %s", (username,))
    data = cursor.fetchone()
    if data is not None:
        if (data[0] or data[1]) is None:
            return ""
        else:
            return data[0] + " " + data[1]
    else:
        return ""


def get_ip():
    return int.from_bytes(inet_aton(request.remote_addr), "big")


def get_useragent(full=False):
    if not full:
        return str(request.user_agent)[:256]
    else:
        return str(request.user_agent)


def get_user_type(username=None):
    if username is None:
        cursor.execute("SELECT `u`.`type` FROM `users` `u` INNER JOIN `sessions` `s` ON `u`.`username` = `s`.`username`"
                       " WHERE `s`.`sess_id` = %s", (request.cookies.get("sessionID"),))
    else:
        cursor.execute("SELECT `type` FROM `users` WHERE `username` = %s", (username,))

    data = cursor.fetchone()
    if data is not None:
        return data[0]
    else:
        return None


def get_userdata(username=None):
    if username is None:
        cursor.execute("SELECT u.`username`, u.`forename`, u.`surname`, u.`attendance`, u.`year` FROM `users` `u` "
                       "INNER JOIN `sessions` ON u.`username` = `sessions`.`username` WHERE `sessions`.`sess_id` = %s",
                       (request.cookies.get("sessionID"),))
    else:
        cursor.execute("SELECT `username`, `forename`, `surname`, `attendance`, `year` FROM `users` WHERE `username` "
                       "= %s", (username,))

    return cursor.fetchone()


def get_username():
    cursor.execute("SELECT u.`username` FROM `users` `u` INNER JOIN `sessions` ON `sessions`.`username` = "
                   "`u`.`username` WHERE `sessions`.`sess_id` = %s", (request.cookies.get("sessionID"),))
    data = cursor.fetchone()
    if data is None:
        return None
    else:
        return data[0]


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
    elif not (any(char in password for char in string.ascii_letters) and
              any(char in password for char in string.digits) and
              any(char not in (string.ascii_letters + string.digits) for char in password)):
        return "Password does not meet password criteria."
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
            print(bans[0])
            if bans:
                cursor.execute("DELETE FROM sessions WHERE username=%s", (session[0],))
                return Bans(bans=bans)
            else:
                if session[1] != get_ip() or session[2] != get_useragent():
                    cursor.execute("DELETE FROM `sessions` WHERE `sess_id` = %s", (cookies.get("sessionID"),))
                    return "IP or system changed. Please log in again to confirm your identity."
                else:
                    return False
        else:
            return "Session timed out."
    else:
        return "No existing session."


def check_ban(ip, username):
    cursor.execute("CALL BANS_REMOVEOLD(); CALL ETC_REMOVEBANNED();", multi=True)

    cursor.execute("SELECT `username`, `ban_ip`, `staff`, `ban_visible`, `ban_reason`, `ban_start`, "
                   "`ban_end` FROM bans WHERE `ban_start` <= NOW()")
    banlist = cursor.fetchall()
    print(banlist[0])

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
    bans = Bans(bans=check_ban(get_ip(), username))
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
