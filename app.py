import secrets
from urllib.parse import urlparse

from flask import Flask, request, make_response, render_template, redirect, url_for, abort
import mysql.connector
from mysql.connector import errorcode
from socket import inet_aton, inet_ntoa
from flask_bcrypt import Bcrypt
import onetimepass
import base64

from wtforms import StringField
from wtforms.validators import DataRequired


class Bans:
    def __init__(self, bans):
        self.bans = bans

class LoginForm:
    username = StringField("Username", validators=DataRequired())


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

app = Flask(__name__)
bcrypt = Bcrypt(app)

try:
    cnx = mysql.connector.connect(user=db_user, password=db_pass, host=db_host, database=db_name)
except mysql.connector.Error as err:
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("ERROR: The username or password for the database is incorrect. [" + err.errno + "]")
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
        print(
            "ERROR: Database does not exist. Please run database setup script [setup.py] or change database name in "
            "web app config. [" + err.errno + "]")
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
        return redirect(url_for("login"), )
    return "This is a test!　私はジョシュアです。"


@app.route("/login", methods=["GET", "POST"])
def login():
    prev = redirect((urlparse(request.referrer).hostname == request.url_root and request.referrer) or url_for(request.args.get("redirect") or "dashboard"), code=302)

    logout = check_logout()
    if not logout:
        return prev
    else:
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            token = request.form.get("token")

            user = cursor.execute("SELECT `password`, `2fa` FROM `users` WHERE `username` = %s", username).fetchone()

            hashed, secret = [user[i] for i in range(2)]

            if user is None: # If there is no user by the given username
                return make_response(render_template("login.html", form=request.form, error="Username or password is incorrect.")).set_cookie("sessionID", "", max_age=0)
            elif hashed is None: # If there is no password set for the user
                return render_template("login.html", form=request.form, error="No password set for account. Please "
                                                                              "select 'reset password'.")
            elif not bcrypt.check_password_hash(hashed, password): # If the password is not correct
                return render_template("login.html", form=request.form, error="Username or password is incorrect.")
            else:
                if not secret:
                    start_session(username)
                    return prev
                else:
                    if onetimepass.valid_hotp(token, secret):
                        start_session(username)
                        return prev
                    else:
                        return render_template("login.html", form=request.form, error="Two Factor Authentication code incorrect.")
        else:
            return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    pass # TODO: Add register function

# Error Handling
@app.errorhandler(451)
def err_legal():
    return render_template("err_451.html"), 451


# Utility functions
def get_ip():
    return int.from_bytes(inet_aton(request.remote_addr), "big")


def get_useragent(full=False):
    if not full:
        return request.user_agent[:256]
    else:
        return request.user_agent


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


def start_session(username):
    origin = (request.referrer and url_for(request.referrer)) or url_for(request.args.get("origin")) or url_for("dashboard")
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


if __name__ == '__main__':
    app.run()
