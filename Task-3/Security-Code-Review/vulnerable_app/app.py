import os
import sqlite3

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret should be supplied through the environment.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "local-development-only-change-this"
)

# Safer session cookie configuration.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE = "notes.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)

    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("demo",)
    ).fetchone()

    if not existing:
        password_hash = generate_password_hash("demo123")

        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("demo", password_hash)
        )

    conn.commit()
    conn.close()


def validate_credentials(username, password):
    if not username or not password:
        return False

    if len(username) < 3 or len(username) > 30:
        return False

    if len(password) < 8 or len(password) > 128:
        return False

    return True


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "script-src 'self'; "
        "img-src 'self' data:;"
    )

    return response


@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_credentials(username, password):
            flash(
                "Username must be 3-30 characters and "
                "password must be at least 8 characters."
            )
            return redirect(url_for("register"))

        conn = get_db()

        try:
            password_hash = generate_password_hash(password)

            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password_hash)
            )

            conn.commit()

            flash("Registration successful. Please login.")
            return redirect(url_for("home"))

        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for("register"))

        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Invalid username or password.")
        return redirect(url_for("home"))

    conn = get_db()

    query = """
        SELECT * FROM users
        WHERE username = ?
    """

    user = conn.execute(
        query,
        (username,)
    ).fetchone()

    conn.close()

    if user and check_password_hash(user["password"], password):
        session.clear()
        session["username"] = user["username"]

        return redirect(url_for("dashboard"))

    flash("Invalid username or password.")
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("home"))

    conn = get_db()

    notes = conn.execute(
        """
        SELECT * FROM notes
        WHERE username = ?
        ORDER BY id DESC
        """,
        (session["username"],)
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        notes=notes
    )


@app.route("/add-note", methods=["POST"])
def add_note():
    if "username" not in session:
        return redirect(url_for("home"))

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if not title or not content:
        flash("Title and content are required.")
        return redirect(url_for("dashboard"))

    if len(title) > 100:
        flash("Title is too long.")
        return redirect(url_for("dashboard"))

    if len(content) > 5000:
        flash("Note content is too long.")
        return redirect(url_for("dashboard"))

    conn = get_db()

    conn.execute(
        """
        INSERT INTO notes (username, title, content)
        VALUES (?, ?, ?)
        """,
        (session["username"], title, content)
    )

    conn.commit()
    conn.close()

    flash("Note added successfully.")
    return redirect(url_for("dashboard"))


@app.route("/delete-note/<int:note_id>", methods=["POST"])
def delete_note(note_id):
    if "username" not in session:
        return redirect(url_for("home"))

    conn = get_db()

    conn.execute(
        """
        DELETE FROM notes
        WHERE id = ? AND username = ?
        """,
        (note_id, session["username"])
    )

    conn.commit()
    conn.close()

    flash("Note deleted.")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
