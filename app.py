import secrets

from flask import Flask, request, make_response, render_template, redirect, url_for
import mysql.connector
from mysql.connector import errorcode
from socket import inet_aton, inet_ntoa
from flask_bcrypt import Bcrypt
import onetimepass
import base64


class Bans:
    def __init__(self, bans):
        self.bans = bans


# CONFIG VALUES
db_user = "root"
db_pass = "$Z8BQb@zktI2Fst@"
db_host = "localhost"
db_name = "portal"

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


def set_user():
    cookies = request.cookies
    global user
    user = {"sessionID": cookies.get("sessionID"),
            "username": cursor.execute("SELECT username FROM sessions WHERE sess_id=%s",
                                       cookies.get("sessionID"))}

    check_login()


set_user()


@app.route("/")
@app.route("/dashboard")
def dashboard():
    return "This is a test!　私はジョシュアです。"


@app.route("/login", methods=["GET", "POST"])
def login():
    logout = check_logout()
    if not logout:
        return redirect(url_for(request.args.get("origin")) or url_for("home"))
    else:
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            token = request.form.get("token")

            user = cursor.execute("SELECT `password`, `2fa` FROM `users` WHERE `username` = %s", username).fetchone()

            hashed, secret = [user[i] for i in range(2)]

            if user is None:
                return render_template("login.html", form=request.form, error="Username or password is incorrect.")
            elif hashed is None:
                return render_template("login.html", form=request.form, error="No password set for account. Please "
                                                                              "select 'reset password'.")
            elif not bcrypt.check_password_hash(hashed, password):
                return render_template("login.html", form=request.form, error="Username or password is incorrect.")
            elif token is None and secret is not None:
                return render_template("login.html", form=request.form, error="Two Factor Authentication is enabled "
                                                                              "on this account. Please enter your 2FA"
                                                                              " code before attempting to log in "
                                                                              "again.")
            elif token:
                if not onetimepass.valid_totp(secret, token):
                    return render_template("login.html", form=request.form, error="Two Factor Authentication code is incorrect.")
                else:
                    start_session(username)
            else:



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
    if not cookies["sessionID"] is None:
        session = cursor.execute("SELECT `sess_id`, `username`, `sess_ip`, `sess_useragent`, FROM `sessions` WHERE "
                                 "`sess_id` = %s", cookies["sessionID"]).fetchone()
        if session:
            bans = check_ban(get_ip(), session[1])
            if bans:
                cursor.execute("DELETE FROM sessions WHERE username=%s", session[1])
                delete_cookie("sessionID")
                return bans
            else:
                if session[2] != get_ip() or session[3] != get_useragent():
                    cursor.execute("DELETE FROM `sessions` WHERE `sess_id` = %s", session[0])
                    delete_cookie("sessionID")
                    return "IP or system changed. Please log in again to confirm your identity."
                else:
                    return False
        else:
            delete_cookie("sessionID")
            return True
    else:
        return False


def check_ban(ip, username):
    bans = cursor.execute("SELECT `ban_admin`, `ban_visible`, `ban_reason`, `ban_start`, `ban_end` FROM bans "
                          "WHERE `ban_start` < NOW() AND `ban_end` > NOW() AND ((`ban_ip`=%d AND `username`=%s) "
                          "OR (`ban_ip` IS NULL and `username`=%s) OR (`ban_ip`=%d AND `username` IS NULL))",
                          (ip, username, username, ip))
    if bans:
        return Bans(bans)
    else:
        return False


def start_session(username):
    bans = check_ban(get_ip(), username)
    if bans:
        pass
        # TODO: Handle banned accounts
    else:
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%&'()*+-./:<=>?@[]^_`{|}~"
        sess_id = "".join(secrets.choice(chars) for i in range(32))

        cursor.execute("INSERT INTO sessions (sess_id, username, sess_start, sess_last, sess_ip, sess_useragent) VALUES"
                       "(%s, %s, NOW(), NOW(), %d, %s)", (sess_id, username, get_ip(), request.user_agent.string))


def end_session():
    if cursor.execute("SELECT TRUE FROM sessions WHERE sess_id=%s", user["sessionID"]).fetchone()[0]:
        cursor.execute("DELETE FROM sessions WHERE sess_id=%s", user["sessionID"])
    delete_cookie("sessionID")
    set_user()  # Sets user dictionary to None values


def delete_cookie(key):
    return make_response().set_cookie(key, "", max_age=0)


if __name__ == '__main__':
    app.run()
