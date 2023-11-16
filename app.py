import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Ensure username was submitted
    stocks = db.execute("SELECT symbol, price, SUM(shares) AS total FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total > 0", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    total_value = cash

    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["value"] = stock["price"] * stock["total"]
        total_value += stock["value"]

    # Redirect user to home page
    return render_template("index.html", stocks = stocks, total_value = total_value, cash = cash)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Buy shares of stock"""
    if request.method == "POST":

        # Ensure username was submitted
        game = request.form.get("game")
        platform = request.form.get("platform")
        if not game:
            return apology("must provide game", 400)
        elif not platform:
            return apology("must provide platform", 400)
        db.execute("INSERT INTO games (user_id, game, platform) VALUES (?, ?, ?)", session["user_id"], game, platform)
        # Redirect user to home page
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("add.html")


@app.route("/list")
@login_required
def list():
    """Show history of transactions"""
    # Ensure username was submitted
    games = db.execute("SELECT * FROM games WHERE user_id = ?", session["user_id"])
    # Redirect user to home page
    return render_template("list.html", games = games)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/info", methods=["GET", "POST"])
@login_required
def info():
    if request.method == "POST":

        # Ensure username was submitted
        game = request.form.get("game")
        if not game:
            return apology("enter valid game", 400)
        return render_template("info.html", game = game)
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("info.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        username = request.form.get("username")
        password = request.form.get("confirmation")
        if password != request.form.get("password"):
            return apology("mismatch password", 400)
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 0:
            return apology("username already exists", 400)


        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, generate_password_hash(password, method='pbkdf2', salt_length=16))
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "POST":
        # Ensure username was submitted
        game = request.form.get("game")
        platform = request.form.get("platform")
        if not game:
            return apology("must provide game", 403)
        elif not platform:
            return apology("must provide platform", 403)
        db.execute("DELETE FROM games WHERE user_id = ? AND game = ? AND platform = ?", session["user_id"], game, platform)
            # Redirect user to home page
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("delete.html")
