"""Deliberately vulnerable Flask app for Sentinel integration tests.

DO NOT deploy. Vulnerabilities are intentional test fixtures.
"""

import sqlite3

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

SECRET_KEY = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
app.config["SECRET_KEY"] = SECRET_KEY


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user/<user_id>")
def show_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/search")
def search_users():
    name = request.args.get("name", "")
    db = get_db()
    cursor = db.cursor()
    query = "SELECT id, name, email FROM users WHERE name LIKE '%" + name + "%'"
    cursor.execute(query)
    return jsonify([dict(r) for r in cursor.fetchall()])


@app.route("/greet")
def greet():
    username = request.args.get("name", "friend")
    return render_template("greeting.html", username=username)


if __name__ == "__main__":
    app.run(debug=True)
