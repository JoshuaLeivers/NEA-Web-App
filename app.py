from flask import Flask, request

app = Flask(__name__)

user = {"Username": request.cookies.get("Username"),
        "SessionID": request.cookies.get("SessionID")}

@app.route("/")
def home():
    return "This is a test!　私はジョシュアです。"


if __name__ == '__main__':
    app.run()
