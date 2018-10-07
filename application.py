#sketch of pset7 cs50

import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
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


@app.route("/")
@login_required
def index():
    rows_of_pf = db.execute("SELECT * FROM portfolios WHERE id = :id", id=session["user_id"])

    if rows_of_pf == []:
        cashier = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        cash = cashier[0]["cash"]
        return render_template("index.html", current_cash=cash, total_cash=cash)
    else:
        #old == [id:1 symbol:FB shares:3]
        #new == [{symbol:FB name: Facebook price: shares:3}]
        new_rows_of_pf = []
        for row in rows_of_pf:
            new_pf_dict = {}
            quote = lookup(row["symbol"])
            new_pf_dict["symbol"] = quote["symbol"]
            new_pf_dict["name"] = quote["name"]
            new_pf_dict["price"] = quote["price"]
            new_pf_dict["shares"] = quote["shares"]
            new_pf_dict["total"] = row["shares"] * quote["price"]

            new_rows_of_pf.append(new_pf_dict)


        cashier = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        cash = cashier[0]["cash"]
        total_cash = cash # + cash from stocks
        for row in new_rows_of_pf:
            total_cash += row["total"]
        return render_template("index.html", rows_of_pf=new_rows_of_pf, current_cash=cash, total_cash=cash)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("missing symbol")

        elif not request.form.get("shares"):
            return apology("missing shares")

        # IF shares are NOT integer
        elif not request.form.get("shares").isdigit():
            return apology("invalid number of shares")

        # storing symbol entered by user in ALL CAPS
        symbol = request.form.get("symbol").upper()

        # using helper function quote to get quote from IEX TRADING
        quote = lookup(symbol)

        # checking IF lookup will fail
        if quote == None:
            return apology("invalid symbol")

        # IF you cannot afford the share
        cashier = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        cash = cashier[0]['cash']

        shares = int(request.form.get("shares"))
        price = quote["price"]
        update_cash = cash - shares * price

        if update_cash < 0:
            return apology("can't afford")

        # Everything OK now: first it updates cash; second update portfolios, third update history table
        # Update the cash in the users table
        db.execute("UPDATE users SET cash = :updated_cash WHERE id = :id", id=session["user_id"], updated_cash=updated_cash)

        # Update the portifolios table symbol by symbol will be selected by user, as well as, the amount
        rows = db.execute("SELECT * FROM portifolios WHERE id=:id AND symbol=:symbol", id=session["user_id"], symbol=symbol)

        # IF there are NO shares of the particular symbol THEN INSERT a new row into portofolios table
        if len(rows) == 0:
            db.execute("INSERT INTO portifolios (id, symbol, shares) VALUES (:id, symbol, :shares", id=session["user_id"], symbol=symbol, shares=shares)
        else:
            db.execute("UPDATE portifolios SET shares = shares + :shares WHERE id=:id", id=session["user_id"], shares=shares)

        # Update the history table
        db.execute("INSERT INTO history (id, symbol, shares, price) VALUES (:id, :symbol, :shares, :price)", id=session["user_id"], symbol=symbol, shares=shares)

        # Return to the index.html
        return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM history WHERE id = :id", id=session["user_id"])
    return render_template("history.html", history_list=rows)
                                        #  history_list (undo)

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
    # IF User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure quote was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol")

        # storing symbol entered by user in ALL CAPS
        symbol = request.form.get("symbol").upper()

        # using helper function quote to get quote from IEX TRADING
        quote = lookup(symbol)

        # checking IF lookup will fail
        if quote == None:
            return apology("invalid symbol")

        return render_template("quoted.html", name=quote["name"], symbol=symbol, price=quote["price"])
    # ELSE IF User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # if the user reached the route via POST = Se o usuario alcançou a rota pelo POST
    if request.method == "POST":
        # ensure that "username" was submitted = ter a certeza de que o nome_de_usuario foi submetido
        if not request.form.get("username"):
            return apology("must provide username")

        # ensure that "password" was submitted = ter a certeza de que a senha foi submetida
        elif not request.form.get("password"):
            return apology("must provide password")

        # ensure that "password_confirmation" was submitted = ter a certeza de que a confirmacao_de_senha foi submetida
        elif not request.form.get("confirmation"):
            return apology("must provide password (again)")

        # ensure password entered is equal to password_confirmation
        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords don't match")

        # All things are OK UNTIL, since, username already taken
        # i.e. SQL_QUERY >> INSERT INTO "users" WHERE (username, hash) VALUES ("username", "some_random_hash"); # hash/encrypt same thing
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                          username=request.form.get("username"),
                          hash=generate_password_hash(request.form.get("password")))
               # obsolete pwd_context.encrypt(request.form.get("password")))
               # obsolete pwd_context.hash(request.form.get("password")))
        if not result:
            return apology("Username Taken")

        # Query database for username
        # IF the user already exists in the DB (table user),
        # THEN say thay you already signed up
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(request.form.get("password"), rows[0]["hash"]):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # ELSE IF the user reached the route via GET = Se o usuario alcançou a rota pelo GET
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # IF the user has submitted the form via POST
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("missing symbol")

        elif not request.form.get("shares"):
            return apology("missing shares")

        # IF shares are NOT integer
        elif not request.form.get("shares").isdigit():
            return apology("invalid number of shares")

        # Storing symbol entered by the user in ALL CAPS
        symbol = request.form.get("symbol").upper()

        # Using helper function quote to get quote from IEX STOCKS
        quote = lookup(symbol)

        # Checking if lookup failed
        if quote == None:
            return apology("invalid symbol")

        # Shares is the number of shares typed in by the user
        shares = int(request.form.get("shares"))

        # Checking if the user has the share he has typed in
        shares_already_list = db.execute("SELECT shares FROM portfolio WHERE id = :id AND symbol = :symbol", id=session["user_id"], symbol = symbol)
        if len(shares_already_list) == 0:
            return apology("symbol not owned")
        shares_already = shares_already_list[0]["shares"]
        updated_shares = shares_alread - shares
        if (updated_shares < 0):
            return apology("too many shares")

        # Price is the current price
        price = quote["price"]

        # It increases the price after selling the shares in variable 'cash_increase'
        cash_increase = price * shares;

        # Update cash from users table
        db.execute("UPDATE users SET cash = cash+cash_increase WHERE id = :id", id=session["user_id"], total_cash=total_cash)

        # Update the portfolio table
        # IF updated shares == 0 THEN delete the row with the symbol
        if updated_shares == 0:
                db.execute("DELETE FROM portfolio WHERE id = :id AND symbol = :symbol", id=session["user_id"], updated_shares=updated_shares) #CONFERIR
        # ELSE
        elif updated_shares > 0:
            db.execute("UPDATE portfolio SET shares = :updated_shares WHERE id=:id", id=session["user_id"], updated_shares=updated_shares)

        # Update the history table (easy) just careful that shares will be negative in sell
        db.execute("INSERT INTO history (id, symbol, shares, price) VALUES (:id, :symbol, :shares, :price)", id=session["user_id"], symbol=symbol, shares=shares)

        return redirect("/")

    # IF the user came here via GET
    else:
        return render_template("sell.html")

@app.route("/password", methods=["GET", "POST"])
def password():
    """Change Password"""
    # IF requested via POST
    if request.method == "POST":
        # Missing information
        if not request.form.get("old_password"):
            return apology("must enter old password")
        elif not request.form.get("new_password"):
            return apology("must enter new password")
        elif not request.form.get("confirmation"):
            return apology("must enter new password again")
        # Confirming the pw an pw again
        if request.form.get("confirmation") != request.form.get("new_password"):
            return apology("passwords don't match")
        # confirming IF the old password is correct
        hashes = db.execute("SELECT hash FROM users WHERE id = :id", id=session['user_id'])
        if check_password_hash(request.form.get("old_password"), hashes[0]["hash"]):
            return apology("old password is wrong")


        # Updating the users table's hash
        db.execute("UPDATE users SET hash = :hash WHERE id=:id", hash=generate_password_hash(request.form.get("new_password")), id=session["user_id"])
        flash("password changed succesfully!")
        return redirect("/")
    else:
        return render_template("password.html")
