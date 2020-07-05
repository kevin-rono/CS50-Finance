# pk_c4f37f7435ed4ee8bd397ae25e67a781

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
@login_required
def index():
    """Show portfolio of stocks"""

    # select required fields from potfolio
    stocks = db.execute("SELECT Symbol, Name, SUM(Shares) AS Shares FROM Bought WHERE ID = :id GROUP BY Symbol",
                        id=session['user_id'])

    # select current cash value from users
    current = db.execute("SELECT cash FROM users WHERE id = :id", id=session['user_id'])

    cash = current[0]["cash"]

    GrandTotal = cash

    # iterate over each row in stocks
    for stock in stocks:
        quote = lookup(stock["Symbol"])
        stock["Price"] = quote["price"]
        stock["Total"] = stock["Price"] * int(stock["Shares"])
        GrandTotal += stock["Total"]

    # render_template in index.html
    return render_template("index.html", stocks=stocks, cash=cash, GrandTotal=GrandTotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # ensure symbol is submitted
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must provide stock symbol")

        # Ensure valid stock
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid Stock Name")

        # ensure number of shares is submitted
        if not request.form.get("shares").isdigit():
            return apology("Must provide number of shares")

        # ensure postive integer
        shares = int(request.form.get("shares"))
        if not shares or shares < 0:
            return apology("Must provide a valid integer for shares")

        # check of user can afford
        rows = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        cash = rows[0]["cash"]

        # look up  stock price
        stockprice = quote["price"]

        # grand total of cash
        totalcost = stockprice * shares

        # return apology if cannot afford
        if not cash or totalcost > cash:
            return apology("Sorry, you cannot afford this stock")

        # New SQL Table
        else:
            db.execute("INSERT INTO Bought ('ID', 'Symbol', 'Name', 'Price', 'Shares', 'Total') VALUES(:id, :symbol, :name, :price, :shares, :total)",
                       id=session["user_id"], symbol=quote["symbol"], name=quote["name"], price=stockprice, shares=shares, total=totalcost)

            # update history
            db.execute("INSERT INTO histories ('Symbol', 'Shares', 'Price', 'ID') VALUES(:symbol, :shares, :price, :id)",
                       symbol=quote["symbol"], shares=shares, price=usd(stockprice), id=session["user_id"])

            # Update cash
            db.execute("UPDATE users SET cash = cash - :purchase WHERE id = :id", id=session["user_id"], purchase=totalcost)

        flash("Bought shares!")

        # redirect user to homepage
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # select from histories and render to history.html
    histories = db.execute("SELECT * FROM histories WHERE ID =:id ORDER BY time DESC", id=session["user_id"])

    return render_template("history.html", histories=histories)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        # Ensure symbol was submmitted
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing stock quote")

        # retrieve stock quote
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid Stock Name", 400)

        return render_template("quoted.html", quote=quote, name=quote["name"], price=quote["price"], symbol=symbol)

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    # Get username
    username = request.args.get("username")

    # Check for username
    if not len(username) or db.execute("SELECT 1 FROM users WHERE username = :username", username=username.lower()):
        return jsonify(False)
    else:
        return jsonify(True)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Missing username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Missing password", 400)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("Missing confirmation", 400)

        # Ensure password and confirmation match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Password and Confirmation do not match")

        # Hash password
        hashed = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # Add user to database
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                            username=request.form.get("username"), hash=hashed)
        if not result:
            return apology("Username not available")

        # log them in
        session["user_id"] = result

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        stocks = db.execute("SELECT Symbol FROM Bought WHERE ID = :id", id=session['user_id'])
        return render_template("sell.html", stocks=stocks)

    # ensure symbol is submitted
    stock = request.form.get("symbol")
    if not stock:
        return apology("Must provide stock symbol")

    # ensure number of shares is submitted
    if not request.form.get("shares"):
        return apology("Must provide number of shares")

    # Ensure valid stock
    quote = lookup(stock)
    if not quote:
        return apology("Invalid Stock Symbol")
    if not request.form.get("shares").isdigit():
        return apology("Must provide positive integer")

    # ensure postive integer
    shares = int(request.form.get("shares"))

    # select the symbol shares of that user
    user_shares = db.execute("SELECT shares FROM Bought WHERE ID = :id AND Symbol=:symbol",
                             id=session["user_id"], symbol=quote["symbol"])

    # check if enough shares to sell
    if user_shares[0]["Shares"] < shares:
        return apology("Not enough shares")

    # update user cash (increase)
    db.execute("UPDATE users SET cash = cash + :sale WHERE id = :id", id=session["user_id"], sale=quote["price"] * shares)

    # otherwise, update portfolio shares count
    if shares < user_shares[0]["Shares"]:
        db.execute("UPDATE Bought SET Shares= shares - :shares WHERE id=:id AND symbol=:symbol",
                   shares=shares, id=session["user_id"], symbol=quote["symbol"])

    # if after decrement is zero, delete shares from portfolio
    elif shares == user_shares[0]["Shares"]:
        db.execute("DELETE FROM Bought WHERE ID=:id AND Symbol=:symbol", id=session["user_id"], symbol=quote["symbol"])

    # update history of a sell
    db.execute("INSERT INTO histories ('Symbol', 'Shares', 'Price', 'ID') VALUES(:symbol, :shares, :price, :id)",
               symbol=quote["symbol"], shares=-shares, price=usd(quote["price"]), id=session["user_id"])

    flash("Sold shares!")

    # redirect user to homepage
    return redirect("/")

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """Deposit cash into account."""

    # if user reached route via GET, return deposit page
    if request.method == "GET":
        return render_template("deposit.html")

    # if user reached via POST i.e. submitting form, check that the form is valid
    elif request.method == "POST":
        if not request.form.get("amount"):
            return apology("Must provide amount")
        if not request.form.get("amount").isdigit():
            return apology("Must provide positive integer")

        # update user's cash amount
        db.execute("UPDATE users SET cash = cash + :amount WHERE id = :id",
                   amount=request.form.get("amount"), id=session["user_id"])
        flash("Deposited cash!")
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
