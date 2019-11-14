from flask import Flask, request, make_response, render_template
from flaskext.mysql import MySQL

app = Flask(__name__)
app.config["MYSQL_DATABASE_USER"] = "portal_man"
app.config["MYSQL_DATABASE_PASSWORD"] = "f8hg30DGt&4svaA4"

mysql = MySQL()
mysql.init_app(app)
cursor = mysql.get_db().cursor()

cookies = request.cookies
user = {"Username": cookies.get("Username"),
        "SessionID": cookies.get("SessionID")}


@app.route("/")
def home():
    return "This is a test!　私はジョシュアです。"


# Utility functions
def check_login():
    template = "login.html"
    sid = user["SessionID"]
    if not sid is None:


if __name__ == '__main__':
    app.run()
