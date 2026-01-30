from flask import Flask, request
import json
import uuid

app = Flask(__name__)

def load_users():
    with open("users.json", "r", encoding="utf-8") as f:
        return json.load(f)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return "не получилось"

    users = load_users()

    if username in users and users[username] == password:
        IDLogin = uuid.uuid4()
        return f"dp {IDLogin}"
    else:
        return "не получилось"

if __name__ == "__main__":
    app.run(debug=True)
