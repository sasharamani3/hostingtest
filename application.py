from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
import time

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure responses aren't cached
if app.config["DEBUG"]:
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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    uniquestocks = db.execute(
        "SELECT DISTINCT ticker FROM transactions where user=:user", user=session["user_id"])

    portfoliovalue = 0.00

    for uniquestock in uniquestocks:
        if uniquestock['ticker'] == "$CASH":
            uniquestocks.remove(uniquestock)

    # Fill the list with the relevant information
    for uniquestock in uniquestocks:
        stock = lookup(uniquestock['ticker'])
        uniquestock['name'] = stock['name']

        rows = db.execute("select sum(quantity) from transactions where user=:user and ticker=:ticker",
                          user=session["user_id"], ticker=stock['symbol'])
        quantity = rows[0]["sum(quantity)"]

        uniquestock['quantity'] = quantity

        uniquestock['price'] = usd(stock['price'])

        stockvalue = quantity * float(stock['price'])
        uniquestock['total'] = usd(stockvalue)

        portfoliovalue += stockvalue

    # Only show stocks that have Quantity > 0
    for uniquestock in uniquestocks:
        if uniquestock['quantity'] == 0:
            uniquestocks.remove(uniquestock)

    rows = db.execute("SELECT cash FROM users WHERE id=:id",
                      id=session["user_id"])

    availablecash = rows[0]["cash"]
    portfoliovalue += availablecash

    return render_template("index.html", stocks=uniquestocks, cash=usd(availablecash), portfolio_value=usd(portfoliovalue))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        ticker = request.form.get("symbol")

        if not request.form.get("symbol"):
            return apology("Must provide symbol", 400)

        quote = lookup(ticker)

        if quote is None:
            return apology("Invalid Quote", 400)

        if not request.form.get("shares"):
            return apology("Must provide # of Shares", 400)

        if not (request.form.get("shares").isdigit()):
            return apology("Invalid # of Shares", 400)

        shares = request.form.get("shares")

        if float(shares) <= 0:
            return apology("Invalid # of Shares", 400)

        # Check integer
        if float(shares) % 1 != 0:
            return apology("Invalid # of Shares", 400)

        totalprice = quote['price'] * int(shares)

        # Get the user's available cash
        rows = db.execute("SELECT cash FROM users WHERE id=:id",
                          id=session["user_id"])

        availablecash = rows[0]["cash"]

        if totalprice > availablecash:
            return apology("Not enough Cash", 403)

        # Update the database
        ticker = ticker.upper()

        db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                   cash=availablecash - totalprice, id=session["user_id"])

        db.execute("INSERT INTO transactions (user, ticker, quantity, value) VALUES (:user, :ticker, :quantity, :value)",
                   user=session["user_id"], ticker=ticker, quantity=int(request.form.get("shares")), value=totalprice)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute(
        "SELECT * FROM transactions where user=:user Order By Datetime Desc", user=session["user_id"])

    rows = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
    endingcash = rows[0]["cash"]
    beginningcash = 0.0

    # Fill the list with the relevant information

    for transaction in transactions:
        beginningcash = endingcash + transaction['value']

        if transaction['ticker'] == "$CASH":

            transaction['ticker'] = ""
            transaction['action'] = "Deposit"
            transaction['price'] = ""
            transaction['quantity'] = ""
            transaction['value'] = usd(-transaction['value'])
            transaction['endingcash'] = usd(endingcash)

        else:
            stock = lookup(transaction['ticker'])

            if transaction['quantity'] >= 0:
                transaction['action'] = "Buy"
            else:
                transaction['action'] = "Sell"

            transaction['price'] = usd(transaction['value'] / transaction['quantity'])

            transaction['quantity'] = abs(transaction['quantity'])
            transaction['value'] = usd(-(transaction['value']))
            transaction['endingcash'] = usd(endingcash)

        endingcash = beginningcash

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username=:username",
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
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        if request.method == "POST":
            return redirect(url_for('quoted', ticker=request.form.get("symbol")))

    else:
        return render_template("quote.html")


@app.route("/quote/<ticker>", methods=["GET", "POST"])
@login_required
def quoted(ticker):
    """Display stock quote."""
    quote = lookup(ticker)

    if quote is None:
        return apology("Invalid Quote", 400)
    else:
        return render_template("quoted.html", name=quote['name'], symbol=quote['symbol'], price=usd(quote['price']))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        elif validpass(request.form.get("password")) == False:
            return apology("pass must contain letters, numbers, and one of !@#$%^&*()")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username=:username",
                          username=request.form.get("username"))

        if len(rows) > 0:
            return apology("Username already exists", 400)

        # Add the user to the database
        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=request.form.get("username"), hash=hash)

        # Now log the user in
        rows = db.execute("SELECT * FROM users WHERE username=:username",
                          username=request.form.get("username"))

        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:   # User reached route via GET (as by clicking a link or via redirect)
        return render_template("register.html")


@app.route("/changepw", methods=["GET", "POST"])
def changepw():
    """Change Password"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        elif not request.form.get("newpassword"):
            return apology("must provide new password", 403)

        elif not request.form.get("newpasswordconfirm"):
            return apology("must confirm new password", 403)

        elif request.form.get("newpassword") != request.form.get("newpasswordconfirm"):
            return apology("new passwords must match", 403)

        elif request.form.get("password") == request.form.get("newpassword"):
            return apology("new password can not match old password", 403)

        elif validpass(request.form.get("newpassword")) == False:
            return apology("pass must contain letters, numbers, and one of !@#$%^&*()")

        # Check Password
        rows = db.execute("SELECT * FROM users WHERE username=:username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Hash the new pw and add it to the database
        hash = generate_password_hash(request.form.get("newpassword"))
        db.execute("UPDATE users SET hash=:hash WHERE username=:username",
                   username=request.form.get("username"), hash=hash)

        # Now log the user in
        rows = db.execute("SELECT * FROM users WHERE username=:username",
                          username=request.form.get("username"))

        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:   # User reached route via GET (as by clicking a link or via redirect)
        return render_template("changepw.html")


@app.route("/addcash", methods=["GET", "POST"])
def addcash():
    """Add Cash"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        cashamt = float(request.form.get("cashamt"))

        # Get Starting Cash Amt
        rows = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        beginningcash = rows[0]["cash"]

        db.execute("INSERT INTO transactions (user, ticker, quantity, value) VALUES (:user, :ticker, :quantity, :value)",
                   user=session["user_id"], ticker="$CASH", quantity=-1, value=-cashamt)

        db.execute("UPDATE users SET cash=:newcash WHERE id=:id",
                   newcash=beginningcash + cashamt, id=session["user_id"])

        # Redirect user to home page
        return redirect("/")

    else:   # User reached route via GET (as by clicking a link or via redirect)
        return render_template("addcash.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # NOTE: Assumes that no short selling is allowed

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        ticker = request.form.get("symbol")

        quote = lookup(ticker)

        if not request.form.get("shares"):
            return apology("must provide # of shares", 400)

        if int(request.form.get("shares")) <= 0:
            return apology("invalid # of shares", 400)

        quantity = int(request.form.get("shares"))

        if quote is None:
            return apology("Invalid Quote", 400)

        # Get the number of shares that the user has of that stock
        ticker = ticker.upper()

        rows = db.execute("select sum(quantity) from transactions where user=:user and ticker=:ticker",
                          user=session["user_id"], ticker=quote['symbol'])

        availablestock = int(rows[0]["sum(quantity)"])

        if quantity > availablestock:
            return apology("Not enough Stock", 400)

        # Get the user's available cash
        rows = db.execute("SELECT cash FROM users WHERE id=:id",
                          id=session["user_id"])

        availablecash = rows[0]["cash"]
        totalprice = quote['price'] * quantity

        # Update the Database
        db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                   cash=availablecash + totalprice, id=session["user_id"])

        db.execute("INSERT INTO transactions (user, ticker, quantity, value) VALUES (:user, :ticker, :quantity, :value)",
                   user=session["user_id"], ticker=ticker, quantity=-quantity, value=-totalprice)

        return redirect("/")

    else:

        uniquestocks = db.execute("SELECT DISTINCT ticker FROM transactions where user=:user",
                                  user=session["user_id"])

        for uniquestock in uniquestocks:
            if uniquestock['ticker'] == "$CASH":
                uniquestocks.remove(uniquestock)

        for uniquestock in uniquestocks:
            stock = lookup(uniquestock['ticker'])

            rows = db.execute("select sum(quantity) from transactions where user=:user and ticker=:ticker",
                              user=session["user_id"], ticker=stock['symbol'])
            quantity = rows[0]["sum(quantity)"]

            uniquestock['quantity'] = quantity

        # Only show stocks that have Quantity > 0
        for uniquestock in uniquestocks:
            if uniquestock['quantity'] == 0:
                uniquestocks.remove(uniquestock)

        return render_template("sell.html", stocks=uniquestocks)


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


def validpass(trialpass):
    """Check that the password has letters, numbers, and valid special characters"""
    alphachars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    numchars = set('0123456789')
    specialchars = set('!@#$%^&*()')

    gotalphachars = False
    gotnumchars = False
    gotspecialchars = False

    if any((c in alphachars) for c in trialpass):
        gotalphachars = True

    if any((c in numchars) for c in trialpass):
        gotnumchars = True

    if any((c in specialchars) for c in trialpass):
        gotspecialchars = True

    return (gotalphachars and gotnumchars and gotspecialchars)


def isvalidnum(trialstring):
    """Check that the inputstring has digits only, thus making it a positive integer"""
    numchars = set('0123456789.-')
    gotbadchars = False

    if any((c not in trialstring) for c in trialstring):
        gotbadchars = True

    return (gotbadchars)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
