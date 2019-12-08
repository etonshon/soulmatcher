import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        elif not request.form.get("newpassword"):
            return apology("must provide new password", 403)
        elif not request.form.get("confirm") or request.form.get("confirm") != request.form.get("newpassword"):
            return apology("confirmation must match new password", 403)
        password = request.form.get("newpassword")
        hash1 = generate_password_hash(password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", (hash1, session["user_id"]))
        return redirect("/")
    else:
        return render_template("changepassword.html")

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol", 403)
        elif request.form.get("shares").isdigit() != True:
            return apology("the value of shares must be a positive integer", 403)
        elif int(request.form.get("shares")) <= 0:
            return apology("the value of shares must be a positive integer", 403)
        shares = request.form.get("shares")
        y = lookup(request.form.get("symbol"))
        symbol = y["symbol"]
        cost = y["price"]
        currentcash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        if float(currentcash[0]["cash"]) < float(shares)*cost:
            return apology("not enough funds", 403)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (currentcash[0]["cash"]-float(shares)*cost, session["user_id"]))
        db.execute("INSERT INTO transactions (shares, price, user_id, symbol, timestamp) VALUES (:shares, :price, :userid, :symbol, CURRENT_TIMESTAMP)",
        shares=int(shares), price=cost, userid=session["user_id"], symbol=symbol)
        return redirect("/")
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = :id ORDER BY id", id=session["user_id"])
    shares = db.execute("SELECT shares FROM transactions WHERE user_id = :id ORDER BY id", id=session["user_id"])
    timestamp = db.execute("SELECT timestamp FROM transactions WHERE user_id = :id ORDER BY id", id=session["user_id"])
    price = db.execute("SELECT price FROM transactions WHERE user_id = :id ORDER BY id", id=session["user_id"])
    length = len(symbols)
    return render_template("history.html", length=length, symbols = symbols, shares=shares, price=price, timestamp=timestamp)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif not request.form.get("confirmation") or request.form.get("confirmation") != request.form.get("password"):
            return apology("confirmation must match password", 403)
        usernames = db.execute("SELECT username FROM users")
        for x in usernames:
            if x["username"] == request.form.get("username"):
                return apology("username already used", 403)
        username = request.form.get("username")
        password = request.form.get("password")
        hash1 = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashhold)", username=username, hashhold=hash1)
        return render_template("login.html")
    else:
        return render_template("register.html")

@app.route("/bio", methods=["GET", "POST"])
def bio():
    if request.method == "POST":
        if not request.form.get("name"):
            return render_template("bio.html", message="Please finish the form")
        elif not request.form.get("email"):
            return render_template("bio.html", message="Please finish the form")
        elif not request.form.get("pnumber"):
            return render_template("bio.html", message="Please finish the form")
        elif not request.form.get("height"):
            return render_template("bio.html", message="Please finish the form")
        elif not request.form.get("age"):
            return render_template("bio.html", message="Please finish the form")
        return render_template("dealbreaker.html")
    else:
        return render_template("bio.html", message="")

@app.route("/dealbreaker", methods=["GET", "POST"])
def dealbreaker():
    if request.method == "POST":
        if not request.form.get("agemax") or not request.form.get("agemin") or not request.form.get("heightmax") or not request.form.get("heightmin"):
            return render_template("dealbreaker.html", message="Please finish the form")
        elif int(request.form.get("heightmax")) < 0 or int(request.form.get("heightmin")) < 0 or int(request.form.get("agemax")) < 0 or int(request.form.get("agemin")) < 0:
            return render_template("dealbreaker.html", message="The value inputed cannot be negative")
        elif request.form.get("agemax") < request.form.get("agemin"):
            return render_template("dealbreaker.html", message="Maximum age must be larger than minimum age")
        elif request.form.get("heightmax") < request.form.get("heightmin"):
            return render_template("dealbreaker.html", message="Maximum height must be larger than minimum height")
        return render_template("personality.html")
    else:
        return render_template("dealbreaker.html", message="")

@app.route("/personality", methods=["GET", "POST"])
def personality():
    print("hi")
    x = request.form.get("result")
    # 'x' REPRESENTS THE PERSONALITY TYPE OF THE PERSON
    IE = request.form.get("IE") # VALUE FOR IE
    NS = request.form.get("NS") # VALUE for NS
    FT = request.form.get("FT") # VALUE for FT
    PJ = request.form.get("PJ") # VALUE for PJ
    UC = request.form.get("UC") # VALUE for UC
    if request.method == "POST":
        return render_template("quoted.html", message = x + " IE:" + IE + " NS:" + NS + " FT:" + FT + " PJ:" + PJ + " UC:" + UC)
    else:
        return render_template("personality.html")

@app.route("/interests", methods=["GET", "POST"])
def interests():
    q1 = request.form.get("q1") # VALUE FOR q1
    q2 = request.form.get("q2") # VALUE for q2
    q3 = request.form.get("q3") # VALUE for q3
    q4 = request.form.get("q4") # VALUE for q4
    q5 = request.form.get("q5") # VALUE for q5
    q6 = request.form.get("q6") # VALUE for q6
    q7 = request.form.get("q7") # VALUE for q7
    q8 = request.form.get("q8") # VALUE for q8
    if request.method == "POST":
        return render_template("quoted.html", message = q1 + q2 + q3 + q4 + q5 + q6 + q7 + q8)
        #return render_template("matchchoice.html")
    else:
        return render_template("interests.html")
@app.route("/matchchoice", methods=["GET", "POST"])
def matchchoice():
    if request.method == "POST":
        choice = request.form.get("choice1")
        if choice == "1":
            return render_template("match.html")
        elif choice == "2":
            return render_template("matchsurvey.html")
        elif choice == "3":
            return render_template("soulmatch.html")
    else:
        return render_template("matchchoice.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        y = lookup(request.form.get("symbol"))
        sellshare = request.form.get("shares")
        sellshare = -int(sellshare)
        symbol = y["symbol"]
        cost = y["price"]
        if request.form.get("shares").isdigit() != True:
            return apology("the value of shares must be a positive integer", 403)
        elif int(request.form.get("shares")) <= 0:
            return apology("the value of shares must be a positive integer", 403)
        currentcash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        currentstock = db.execute("SELECT SUM(shares) FROM transactions WHERE symbol = ? AND user_id = ?", ((y["symbol"]), session["user_id"]))
        print(currentstock[0]['SUM(shares)'])
        print(sellshare)
        if abs(sellshare) > int(currentstock[0]['SUM(shares)']):
            return apology("Not enough stocks in portfolio", 403)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (currentcash[0]["cash"]-sellshare*cost, session["user_id"]))
        db.execute("INSERT INTO transactions (shares, price, user_id, symbol, timestamp) VALUES (:shares, :price, :userid, :symbol, CURRENT_TIMESTAMP)",
        shares=sellshare, price=cost, userid=session["user_id"], symbol=symbol)
        return redirect("/")
    else:
        symbol = db.execute("SELECT DISTINCT symbol FROM transactions WHERE user_id = ? ORDER BY symbol", (session["user_id"]))
        return render_template("sell.html", symbol=symbol)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
