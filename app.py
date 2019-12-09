from flask import Flask, request, make_response, render_template
import mysql.connector
from mysql.connector import errorcode
from socket import inet_aton, inet_ntoa

# CONFIG VALUES
db_user = "portal_man"
db_pass = "f8hg30DGt&4svaA4"
db_name = "portal"

app = Flask(__name__)

try:
    cnx = mysql.connector.connect(user=db_user, password=db_pass, database=db_name)
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


def set_cookies():
    global user
    user = {"sessionID": cookies.get("sessionID"),
            "username": cursor.execute("SELECT username FROM sessions WHERE sess_id=%s",
                                       request.cookies.get("username"))}


set_cookies()


@app.route("/")
@app.route("/dashboard")
def home():
    return "This is a test!　私はジョシュアです。"


# Utility functions
def get_ip():
    return int.from_bytes(inet_aton(request.remote_addr), "big")


def check_login():
    template = "login.html"
    set_cookies()
    if not user["sessionID"] is None:
        if check_ban():
            cursor.execute("DELETE FROM sessions WHERE username=%s", user["username"])
            end_session()
        else:
            sess = cursor.execute("SELECT sess_ip, sess_useragent FROM sessions WHERE sid=%s", sid).fetchone()
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
    set_cookies()

    row = cursor.execute("SELECT ban_admin, ban_adminvisible, ban_reason, ban_start, ban_end FROM bans WHERE "
                         "ban_start < NOW() AND ban_end > NOW() AND ((ban_ip=%d AND username=%s) OR (ban_ip IS "
                         "NULL and username=%s) OR (ban_ip=%d AND username IS NULL))", (user["ip"],
                                                                                        user["username"],
                                                                                        user["username"],
                                                                                        user["ip"])).fetchone()
    return row


def end_session():
    cursor.execute("DELETE FROM sessions WHERE sess_id=%s", user["sessionID"])
    delete_cookie("sessionID")
    delete_cookie("username")
    set_cookies()


def delete_cookie(key):
    return make_response().set_cookie(key, "", max_age=0)


if __name__ == '__main__':
    app.run()
