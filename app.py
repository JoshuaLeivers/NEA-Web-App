import secrets
import time
from urllib.parse import urlparse

from flask import Flask, request, make_response, render_template, redirect, url_for, abort, flash
import mysql.connector
from flask_wtf import FlaskForm, CSRFProtect
from mysql.connector import errorcode
from socket import inet_aton, inet_ntoa
from flask_bcrypt import Bcrypt
import onetimepass
import base64

from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, NoneOf, InputRequired


class Bans:
    def __init__(self, bans):
        self.bans = bans


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    token = StringField("Token", validators=[Length(6, 6)])
    submit = SubmitField("Sign In")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(1, 64, message="Username must be between "
                                                                                          "1-64 characters in "
                                                                                          "length.")])
    submit = SubmitField("Register")


class RegisterConfirmForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired(), Length(10, 72, message="Passwords must be "
                                                                                            "between 10 and 72 "
                                                                                            "characters long.")])
    password_confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    tfa = BooleanField("Setup Two Factor Authentication?")
    submit = SubmitField("Confirm")


class RegisterTFAForm(FlaskForm):
    token = StringField("Token", validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField("Verify")


# CONFIG VALUES
db_user = "root"
db_pass = "$Z8BQb@zktI2Fst@"
db_host = "localhost"
db_name = "portal"

email = {
    "legal": "joshua@leivers.dev",
    "webmaster": "joshua@leivers.dev",
    "enquiries": "joshua@leivers.dev"
}

limits = {
    "requests": {
        "ip": 20,
        "username": 5
    }
}

app = Flask(__name__)
app.config["SECRET_KEY"] = b'\xd91Oi~i\xcc\xdb5\xffWT\xea\xa2\xf6\xeb'  # Generated by os.urandom(16)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

try:
    cnx = mysql.connector.connect(user=db_user, password=db_pass, host=db_host, database=db_name, autocommit=True)
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


@app.route("/")
@app.route("/dashboard")
def dashboard():
    if check_logout():
        resp = make_response(redirect(url_for("login")))
        resp.set_cookie("sessionID", "", max_age=0)
        return resp
    return render_template("dashboard.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    origin = get_redirect("login")
    logout = check_logout()
    if not logout:
        # TODO: Make a separate function that decides which ban page to display, then add a check here to use it
        return redirect(origin, 302)
    else:
        form = LoginForm()
        if form.validate_on_submit():
            user = cursor.execute("SELECT `password`, `2fa` FROM `users` WHERE `username` = %s", [form.username.data])
            if user is not None:  # If there is a user by the given username
                user = user.fetchone()
                hashed, secret = [user[i] for i in range(2)]

                if hashed is None:  # If there is no password set for the user
                    return redirect(url_for("reset") + "?user=" + form.username.data, code=303)
                elif not bcrypt.check_password_hash(hashed, form.password.data):  # If the password is not correct
                    return render_template("login.html", form=form, error="Username or password is incorrect.")
                else:
                    if not secret:
                        return start_session(form.username.data, origin)
                    else:
                        if onetimepass.valid_totp(form.token.data, secret):
                            return start_session(form.username.data, origin)
            else:
                flash("Username or password is incorrect.")
                resp = make_response(
                    render_template("login.html", form=form, error="Username or password is incorrect."))
                resp.set_cookie("sessionID", "", max_age=0)
                return resp
        else:
            return make_response(render_template("login.html", title="Sign In", form=form))


@app.route("/register", methods=["GET", "POST"])
def register():
    if not check_logout():
        return redirect(get_redirect("register"))
    else:
        form = RegisterForm()
        if form.validate_on_submit():
            cursor.execute("DELETE FROM `requests` WHERE `req_time` < DATE_SUB(NOW(), INTERVAL 30 MINUTE)")

            username = form.username.data
            cursor.execute("SELECT TRUE FROM `users` WHERE `username` = %s", (username,))
            if not cursor.fetchall():
                cursor.execute("SELECT TRUE FROM `requests` WHERE `req_ip` = %s", (get_ip(),))
                if len(cursor.fetchall()) >= limits["requests"]["ip"]:
                    flash("Too many registration requests have been made from this IP. Please try again later.")
                    return render_template("register.html", title="Register", form=form, email=email["webmaster"]), 429
                else:
                    cursor.execute("SELECT TRUE FROM `requests` WHERE `req_username` = %s", (username,))
                    if len(cursor.fetchall()) >= limits["requests"]["username"]:
                        flash(
                            "Too many registration requests have been made for this username. Please try again later.")
                        return render_template("register.html", title="Register", form=form,
                                               email=email["webmaster"]), 429
                    else:
                        req_id = secrets.token_urlsafe(48)  # As this is Base64 encoded, this is 64 characters long
                        cursor.execute("SELECT TRUE FROM `requests` WHERE `req_id` = %s", (req_id,))
                        while cursor.fetchall():
                            req_id = secrets.token_urlsafe(48)
                            cursor.execute("SELECT TRUE FROM `requests` WHERE `req_id` = %s", (req_id,))

                        print("Creating request " + req_id)
                        cursor.execute("INSERT INTO `requests` (`req_id`, `req_username`, `req_time`, `req_useragent`, "
                                       "`req_ip`) VALUES (%s, %s, %s, %s, %s)", (req_id, username, time.strftime(
                            "%Y-%m-%d %H:%M:%S"), get_useragent(), get_ip()))
                        print("Created request.")

                        return make_response(render_template("registered.html", title="Registered", username=username,
                                                             redirect=url_for("login")))
            else:
                flash("A user already exists using the given username.")
                return render_template("register.html", title="Register", form=form, email=email["webmaster"]), 403
        else:
            return render_template("register.html", title="Register", form=form, email=email["webmaster"])


@app.context_processor
def inject_user_type():
    return dict(user_type=get_user_type())


# Error Handling
@app.errorhandler(451)
def err_legal():
    return render_template("err_451.html"), 451


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
    return cursor.fetchone()


def check_logout():
    cookies = request.cookies
    if not cookies.get("sessionID") is None:
        session = cursor.execute("SELECT `sess_id`, `username`, `sess_ip`, `sess_useragent`, FROM `sessions` WHERE "
                                 "`sess_id` = %s", cookies.get("sessionID")).fetchone()
        if session:
            bans = check_ban(get_ip(), session[1])
            if bans:
                cursor.execute("DELETE FROM sessions WHERE username=%s", session[1])
                return bans
            else:
                if session[2] != get_ip() or session[3] != get_useragent():
                    cursor.execute("DELETE FROM `sessions` WHERE `sess_id` = %s", session[0])
                    return "IP or system changed. Please log in again to confirm your identity."
                else:
                    return False
        else:
            return True
    else:
        return True


def check_ban(ip, username):
    banlist = cursor.execute("SELECT `username`, `ban_ip`, `ban_admin`, `ban_visible`, `ban_reason`, `ban_start`, "
                             "`ban_end` FROM bans WHERE `ban_start` < NOW() AND `ban_end` > NOW() AND ((`ban_ip`=%d "
                             "AND `username`=%s) OR (`ban_ip` IS NULL and `username`=%s) OR (`ban_ip`=%d AND "
                             "`username` IS NULL))", (ip, username, username, ip))

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
    if bans:
        return Bans(bans)
    else:
        return False


def start_session(username, origin):
    bans = check_ban(get_ip(), username)
    if bans:
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
    else:
        # These are the characters allowed within a cookie value
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%&'()*+-./:<=>?@[]^_`{|}~"
        sess_id = "".join(secrets.choice(chars) for i in range(32))

        cursor.execute("INSERT INTO sessions (sess_id, username, sess_start, sess_last, sess_ip, sess_useragent) VALUES"
                       "(%s, %s, NOW(), NOW(), %d, %s)", (sess_id, username, get_ip(), request.user_agent.string))

        resp = redirect((request.referrer and url_for(request.referrer)[:request.url_root.len] == request.url_root) or
                        url_for(request.args.get("redirect")) or url_for("home"), 302)
        resp.set_cookie("sessionID", sess_id, max_age=None, samesite=True, secure=True, httponly=True)
        return resp


def get_redirect(this):
    origin = request.args.get("redirect")
    if origin:
        return url_for(origin)

    origin = request.referrer
    print(origin, request.url_root, request.host, request.host_url)
    if urlparse(origin).hostname == request.url_root and origin != url_for(this):
        return origin

    return url_for("dashboard")


if __name__ == '__main__':
    app.run()
