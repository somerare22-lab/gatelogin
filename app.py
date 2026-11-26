import hashlib
import os
import secrets
import sqlite3
import string
import uuid

from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

DATABASE = os.environ.get("GATELOGIN_DATABASE", "gatelogin.sqlite3")
TOKEN_LENGTH = 255
TOKEN_ALPHABET = string.ascii_letters + string.digits


def connect_db():
    connection = sqlite3.connect(DATABASE, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with connect_db() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                token_hash TEXT UNIQUE
            )
            """
        )


def read_credentials():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None, None
    return username.strip(), password


def make_token():
    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))


def hash_token(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def get_request_token():
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        return authorization[7:].strip()
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        token = data.get("token")
        if isinstance(token, str):
            return token
    return None


@app.get("/")
def index():
    return jsonify({
        "name": "GateLogin",
        "status": "running",
        "api": ["/register", "/login", "/verify", "/logout"]
    })


@app.post("/register")
def register():
    username, password = read_credentials()
    if not username or not password:
        return jsonify(error="username and password are required"), 400
    if len(username) > 64 or len(password) < 8 or len(password) > 256:
        return jsonify(error="username must be at most 64 characters; password must be 8-256 characters"), 400

    user_uuid = str(uuid.uuid4())
    password_hash = generate_password_hash(password)

    try:
        with connect_db() as db:
            db.execute(
                "INSERT INTO users (uuid, username, password_hash) VALUES (?, ?, ?)",
                (user_uuid, username, password_hash)
            )
    except sqlite3.IntegrityError:
        return jsonify(error="username already exists"), 409

    return jsonify(uuid=user_uuid, message="account created"), 201


@app.post("/login")
def login():
    username, password = read_credentials()
    if not username or not password:
        return jsonify(error="username and password are required"), 400

    with connect_db() as db:
        user = db.execute(
            "SELECT uuid, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            return jsonify(error="invalid username or password"), 401

        token = make_token()
        db.execute(
            "UPDATE users SET token_hash = ? WHERE uuid = ?",
            (hash_token(token), user["uuid"])
        )

    return jsonify(uuid=user["uuid"], token=token, token_length=TOKEN_LENGTH)


@app.post("/verify")
def verify():
    token = get_request_token()
    if not token or len(token) != TOKEN_LENGTH or not token.isascii() or not token.isalnum():
        return jsonify(valid=False), 401

    with connect_db() as db:
        user = db.execute(
            "SELECT uuid, username FROM users WHERE token_hash = ?",
            (hash_token(token),)
        ).fetchone()

    if user is None:
        return jsonify(valid=False), 401

    return jsonify(valid=True, uuid=user["uuid"], username=user["username"])


@app.post("/logout")
def logout():
    token = get_request_token()
    if not token:
        return jsonify(error="token is required"), 400

    with connect_db() as db:
        cursor = db.execute(
            "UPDATE users SET token_hash = NULL WHERE token_hash = ?",
            (hash_token(token),)
        )

    if cursor.rowcount == 0:
        return jsonify(error="token not found or already revoked"), 401

    return jsonify(success=True, message="token revoked")


init_db()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("GATELOGIN_HOST", "127.0.0.1"),
        port=int(os.environ.get("GATELOGIN_PORT", "5000")),
        debug=False
    )
