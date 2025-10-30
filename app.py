import os
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import (
    LoginManager, UserMixin, login_user, current_user,
    login_required, logout_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------
# Flask Setup
# -------------------------
app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------------
# Database Model
# -------------------------
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(int(user_id))

# -------------------------
# Routes
# -------------------------

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/venues")
def venues():
    return render_template("venues.html")

@app.route("/announcements")
def announcements():
    return render_template("announcements.html")

@app.route("/mayhem")
def mayhem():
    return render_template("mayhem.html")

@app.route("/fights")
def fights():
    return render_template("fights.html")

# -------------------------
# Login / Register Combined
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["uname"].strip()
        password = request.form["psw"].strip()

        if not username or not password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("login"))

        user = Users.query.filter_by(username=username).first()

        if user:
            # User exists → verify password
            if not check_password_hash(user.password, password):
                flash("Invalid password.", "error")
                return redirect(url_for("login"))

            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("index"))

        else:
            # No user → auto-register
            hashed_pw = generate_password_hash(password)
            new_user = Users(username=username, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash("New account created and logged in.", "success")
            return redirect(url_for("index"))

    return render_template("login.html")

# -------------------------
# Run Server
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)
