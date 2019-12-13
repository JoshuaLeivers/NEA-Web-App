import secrets

from flask import Flask, request, make_response, render_template, redirect, url_for
import mysql.connector
from mysql.connector import errorcode
from socket import inet_aton, inet_ntoa
from flask.ext.bcrypt import Bcrypt
import onetimepass
import base64

# CONFIG VALUES
db_user = "portal_man"
db_pass = "f8hg30DGt&4svaA4"
db_host = "localhost"
db_name = "portal"

app = Flask(__name__)
bcrypt = Bcrypt(app)

try:
    cnx = mysql.connector.connect(user=db_user, password=db_pass, host=db_host, database=db_name)
except mysql.connector.Error as error:
    if error.errno == errorcode.ER_ACCESS_DENIED_ERROR:
        print("The username or password for the database is incorrect.")
    elif error.errno == errorcode.ER_BAD_DB_ERROR:
        print(
            "Database does not exist. Please run database setup script [setup.py] or change database name in web app.")
    else:
        print(error)
else:
    cursor = cnx.cursor()

cookies = request.cookies


def set_user():
    global user
    user = {"sessionID": cookies.get("sessionID"),
            "username": cursor.execute("SELECT username FROM sessions WHERE sess_id=%s",
                                       cookies.get("sessionID"))}

    check_login()


set_user()


@app.route("/")
@app.route("/dashboard")
@app.route("/home")
def dashboard():
    return "This is a test!　私はジョシュアです。"


@app.route("/login", methods=["GET", "POST"])
def login():
    if check_login():
        return redirect(url_for(request.args.get("origin")) or url_for("home"))
    else:
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            tfa = request.form.get("2fa")

            hashed, secret = [cursor.execute("SELECT password, 2fa FROM users WHERE username = %s", username).fetchone()[i] for i in range(2)]

            if hashed is None or not bcrypt.check_password_hash(hashed, password):
                return render_template("login.html", form=request.form, error="Username or password is incorrect")
            elif tfa is None:
                start_session(username)


# Utility functions
def get_ip():
    return int.from_bytes(inet_aton(request.remote_addr), "big")


def check_login():
    template = "login.html"
    set_user()
    if not user["sessionID"] is None:
        if check_ban():
            cursor.execute("DELETE FROM sessions WHERE username=%s", user["username"])
            end_session()
        else:
            sess = cursor.execute("SELECT sess_ip, sess_useragent FROM sessions WHERE sid=%s", user["sessionID"]).fetchone()
            if sess:
                if sess[0] != user["ip"] or sess[1] != get_ip():
                    end_session()
                    return False
                else:
                    return True
            else:
                end_session()
                return False
    else:
        return False


def check_ban():
    set_user()

    row = cursor.execute("SELECT ban_admin, ban_adminvisible, ban_reason, ban_start, ban_end FROM bans WHERE "
                         "ban_start < NOW() AND ban_end > NOW() AND ((ban_ip=%d AND username=%s) OR (ban_ip IS "
                         "NULL and username=%s) OR (ban_ip=%d AND username IS NULL))", (user["ip"],
                                                                                        user["username"],
                                                                                        user["username"],
                                                                                        user["ip"])).fetchone()
    return row


def start_session(username):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%&'()*+-./:<=>?@[]^_`{|}~"
    sess_id = "".join(secrets.choice(chars) for i in range(32))

    cursor.execute("INSERT INTO sessions (sess_id, username, sess_start, sess_last, sess_ip, sess_useragent) VALUES ("
                   "%s, %s, NOW(), NOW(), %d, %s)", (sess_id, username, get_ip(), request.user_agent.string))


def end_session():
    if cursor.execute("SELECT TRUE FROM sessions WHERE sess_id=%s", user["sessionID"]).fetchone()[0]:
        cursor.execute("DELETE FROM sessions WHERE sess_id=%s", user["sessionID"])
    delete_cookie("sessionID")
    set_user()  # Sets user dictionary to None values


def delete_cookie(key):
    return make_response().set_cookie(key, "", max_age=0)


if __name__ == '__main__':
    app.run()
