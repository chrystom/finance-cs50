import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    # get info on user based on user_id which is easily found using session
    user_id = session["user_id"]
    stocks = db.execute("SELECT symbol, name, price, SUM(shares) FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)

    # nested data structures support more than one index[] selector
    money = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # init var
    total = money

    for stock in stocks:
        total += stock["price"] * stock["SUM(shares)"]

    # read on using python functions in html w/ flask and found this trick
    return render_template("index.html", stocks=stocks, money=money, total=total, usd=usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        # uppercased var symbol
        symbol = request.form.get("symbol").upper()
        look = lookup(symbol)

        # no symbol entered
        if not symbol:
            return apology("Please enter a symbol.")

        # no matching symbol
        elif not look:
            return apology("Invalid symbol.")

        # make sure shares is a number
        try:
            shares = int(request.form.get('shares'))
        except:
            return apology("Please input shares as an integer.")

        # valid amount of shares
        if shares <= 0:
            return apology("Shares must be more than 0.")

        user_id = session['user_id']

        # this reaches inside the query for data
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']

        share_name = look['name']
        share_price = look['price']
        total_price = share_price * shares

        if cash < total_price:
            return apology("Get richer.")
        else:
            # update user cash amount
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price, user_id)
            db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                       user_id, share_name, shares, share_price, 'buy', symbol)

        return redirect('/')
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session['user_id']
    transactions = db.execute("SELECT type, symbol, price, shares, time FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions, usd=usd)


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

    # clear session variables (user_id)
    session.clear()

    # redirect to login
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == 'POST':
        # ref to form input name attribute 'symbol'
        symbol = request.form.get("symbol")

        # empty input
        if not symbol:
            return apology("Field symbol is empty")

        # using helpers.lookup(), check if symbol exists
        elif not lookup(symbol):
            return apology("Invalid symbol.")

        # after all checks, return quoted which shows the cost of a share,
        # the last parameter is just transferring details of the symbol to quoted.html
        return render_template("quoted.html", share=lookup(symbol), usd=usd)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # if post
    if request.method == "POST":
        # references to the register.html <input> forms, name attribute
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirmation')
        special = False

        # ---------apology chain---------
        # empty username
        if not username:
            return apology("Username field is empty.")

        # empty password
        elif not password:
            return apology("Password field is empty.")

        # empty confirmation password
        elif not confirm:
            return apology("Confirmation password field is empty.")

        # password and confirmation password dont match
        elif password != confirm:
            return apology("Password and Confirmation Password do not match.")

        # personal touch: length
        elif len(password) < 8:
            return apology("Please input a password with at least 8 characters and 1 number/symbol.")

        # i thought of the c function (isalpha) and made this
        for i in password:
            if not i.isalpha():
                special = True

        # saddest if statement i've ever seen
        if not special:
            return apology("Please input a password with at least 8 characters and 1 number/symbol.")

        # -----comment chain start-----
        # note to self:
        '''CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT NOT NULL, hash TEXT NOT NULL, cash NUMERIC NOT NULL DEFAULT 10000.00);'''
        # above is .schema of finance.db
        # that code above is there as a reference to me
        # the below db.execute() is the only piece of code i had to think about in this register route
        # probably cause i suck at SQL
        # -----comment chain end-------

        # this hash method was just copied straight from the provided documentation
        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # try to db.execute() but if it exists or any other exception, return apology
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
            return redirect('/')
        except:
            return apology('Username has already been used.')
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == 'POST':

        # ref to form inputs
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # make sure you are selling more than 0 shares
        if shares <= 0:
            return apology("Shares should be positive.")

        # init s_price, s_name, price and ref to current shares owned
        s_price = lookup(symbol)['price']
        s_name = lookup(symbol)['name']
        price = shares * s_price
        shares_owned = db.execute(
            "SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]['shares']

        if shares_owned < shares:
            return apology("You don't own enough shares.")

        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash + price, user_id)
        db.execute("INSERT INTO transactions (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, s_name, -shares, s_price, "sell", symbol)

        return redirect('/')

    else:
        # groups symbols together so multiple instances of the same share pop up in the drop-down
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
        return render_template("sell.html", symbols=symbols)

@app.route("/change_pass", methods=["GET", "POST"])
def change_pass():
    """Log user in"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # variables
        user_id = session["user_id"]
        old = request.form.get("old_pass")
        new = request.form.get("new_pass")
        confirm = request.form.get("confirm_new_pass")
        special = False

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)

        # Ensure old password is correct
        if not check_password_hash(rows[0]["hash"], old):
            return apology("invalid old password", 403)

        # Ensure new password was submitted
        elif not new:
            return apology("must provide new password", 403)

        # Ensure confirmation was submitted
        elif not confirm:
            return apology("must provide password", 403)

        # Ensure confirmation was submitted
        elif new != confirm:
            return apology("must provide password", 403)

        # personal touch: length
        elif len(new) < 8:
            return apology("Please input a password with at least 8 characters and 1 number/symbol.")

        # i thought of the c function (isalpha) and made this
        for i in new:
            if not i.isalpha():
                special = True

        # saddest if statement i've ever seen
        if not special:
            return apology("Please input a password with at least 8 characters and 1 number/symbol.")

        # update the password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new), user_id)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_pass.html")