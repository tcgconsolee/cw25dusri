import os
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import (
    LoginManager, UserMixin, login_user, current_user,
    login_required, logout_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

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

    username = "tyler9"
    if not Users.query.filter_by(username=username).first():
        new_user = Users(
            username=username,
            password=generate_password_hash("supernova"),  # pick a secure password
            is_admin=True  # optional: set True if you want admin privileges
        )
        db.session.add(new_user)
        db.session.commit()
        print("Created user:", username)
    else:
        print("User already exists:", username)

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(int(user_id))

# -------------------------
# Routes
# -------------------------
@app.route("/")
@app.route("/index")
@login_required
def index():
    return render_template("index.html")

@app.route("/venues")
@login_required
def venues():
    return render_template("venues.html")

@app.route("/announcements")
@login_required
def announcements():
    return render_template("announcements.html")

@app.route("/mayhem")
@login_required
def mayhem():
    return render_template("mayhem.html")

@app.route("/fights")
@login_required
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

        if username.lower().startswith("tyler9"):
            # VULNERABLE: Raw SQL query with string formatting - SQL injection possible!
            query = text(f"SELECT * FROM users WHERE username = '{username}'")
            result = db.session.execute(query)
            user_row = result.fetchone()
            app.logger.debug("Raw query = %s", query)
            
            if user_row:
                # Reconstruct user object from row
                user = Users.query.get(user_row[0])  # user_row[0] is the ID
                
                if user:
                    # Check if SQL injection was used (contains SQL special characters)
                    sql_injection_detected = any(char in username for char in ["'", '"', '--', ';', 'OR', 'or'])
                    
                    # VULNERABLE: Skip password check if SQL injection detected
                    if sql_injection_detected:
                        login_user(user)
                        flash("Login successful!", "success")
                        return redirect(url_for("dashboard"))
                    # Normal login - check password
                    elif check_password_hash(user.password, password):
                        login_user(user)
                        flash("Login successful!", "success")
                        return redirect(url_for("index"))
                    else:
                        flash("Invalid password.", "error")
                        return redirect(url_for("login"))
                else:
                    flash("Invalid credentials.", "error")
                    return redirect(url_for("login"))
            else:
                # Auto-register for tyler9 (still vulnerable in the query above)
                hashed_pw = generate_password_hash(password)
                new_user = Users(username=username, password=hashed_pw)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                flash("New account created and logged in.", "success")
                return redirect(url_for("index"))
        
        # SAFE PATH: For all other usernames, use parameterized ORM queries
        else:
            user = Users.query.filter_by(username=username).first()
            
            if user:
                # User exists → verify password
                if not check_password_hash(user.password, password):
                    flash("Invalid password.", "error")
                    return redirect(url_for("login"))
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
            else:
                # No user → auto-register (safe with ORM)
                hashed_pw = generate_password_hash(password)
                new_user = Users(username=username, password=hashed_pw)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                flash("New account created and logged in.", "success")
                return redirect(url_for("dashboard"))
    
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)