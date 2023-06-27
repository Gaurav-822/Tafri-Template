import os

from sqlalchemy import create_engine, MetaData, Table, Column, Integer, Text, text, delete, insert
from sqlalchemy.sql.expression import update, select

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session

from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure Application
app = Flask(__name__)

# Ensure templates are auto reloded
app.config["TEMPLATES_AUTO_RELOD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Making connection to the database
engine = create_engine("sqlite:///data.db", echo = False, connect_args={"check_same_thread": False})
conn = engine.connect()

# Make Tables:
meta = MetaData()
users = Table(
    'users', meta,
    Column('id', Integer, primary_key = True),
    Column('username', Text),
    Column('hash', Text),
    Column('exclusive', Integer),
)

ms = Table(
    'ano', meta,
    Column('msg', Text),
    Column('public', Integer),
)

meta.create_all(engine)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]

    if session['user_id'] and req == 1:
        return render_template('exclusive_home.html', req=1)
    else:
        return render_template('general_home.html', req=0)

@app.route("/home")
def home():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]

    if session['user_id'] and req == 1:
        return render_template('exclusive_home.html', req=1)
    else:
        return render_template('general_home.html', req=0)

@app.route("/content", methods=["GET", "POST"])
# @login_required
def ano():
    if request.method == "POST":
        t = request.form.get("msg")
        conn.execute(ms.insert().values(msg = t, public = 0))
        return render_template('ano.html')
    else:
        return render_template("ano.html")



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
        #Can make better
        user = text('SELECT username, hash, id, exclusive FROM users')
        result = conn.execute(user)
        u_l = []
        id = 0
        for row in result:
            if row[0] == request.form.get("username"):
                if check_password_hash(row[1], request.form.get("password")):
                    session['user_id'] = row[2]
                    if row[3] == 1:
                        return render_template('exclusive.html', req=1)
                    else:
                        return render_template('general_home.html', req=0)
        
        return apology('Sorry We cannot find you right now')
    
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
    """Register user"""
    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get('username')
    password = request.form.get('password')
    confirmation = request.form.get('confirmation')

    user = text('SELECT username, id FROM users')
    result = conn.execute(user)
    u_l = []
    id = 0
    for row in result:
        u_l.append(row[0])
        id = row[1]
    if username == '' or username in u_l:
        return apology('input is blank or the username already exists.')
    u_l = []
    if password == '' or password != confirmation:
        return apology('Password input is blank or the passwords do not match.')

    # id = db.execute('INSERT INTO users(username, hash) VALUES(?, ?)', username, generate_password_hash(password))
    ins = users.insert().values(username = username, hash = generate_password_hash(password), exclusive = 0)
    conn.execute(ins)

    return render_template('pending.html')


@app.route("/about")
@login_required
def about():
    return render_template('about.html')

# Accounts : 
@app.route("/sid")
@login_required
def sid():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('sid.html', req=req)

@app.route("/shivam")
@login_required
def shivam():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('shivam.html', req=req)

@app.route("/debasish")
@login_required
def debasish():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('debasish.html', req=req)

@app.route("/gaurav")
@login_required
def gaurav():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('gaurav.html', req=req)

@app.route("/sarthak_jha")
@login_required
def sarthak_jha():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('sarthak_jha.html', req=req)

@app.route("/saumyabrat")
@login_required
def saumyabrat():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('saumyabrat.html', req=req)

@app.route("/aman")
@login_required
def aman():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('aman.html', req=req)

@app.route("/dibyanshu")
@login_required
def dibyanshu():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('dibyanshu.html', req=req)

@app.route("/aryan")
@login_required
def aryan():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('aryan.html', req=req)

@app.route("/srinjoy")
@login_required
def srinjoy():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('srinjoy.html', req=req)

@app.route("/sohel")
@login_required
def sohel():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('sohel.html', req=req)

@app.route("/deepjyoti")
@login_required
def deepjyoti():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('deepjyoti.html', req=req)

@app.route("/ankit")
@login_required
def ankit():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('ankit.html', req=req)

@app.route("/bitopan")
@login_required
def bitopan():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('bitopan.html', req=req)

@app.route("/arihant")
@login_required
def arihant():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('arihant.html', req=req)

@app.route("/sarthak_srivastav")
@login_required
def sarthak_srivastav():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('sarthak_srivastav.html', req=req)

@app.route("/sashwata")
@login_required
def sashwata():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('sashwata.html', req=req)

@app.route("/ritwij")
@login_required
def ritwij():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('ritwij.html', req=req)

@app.route("/priyangshu")
@login_required
def priyangshu():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('priyangshu.html', req=req)

@app.route("/sumit")
@login_required
def sumit():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('sumit.html', req=req)

@app.route("/kaushik")
@login_required
def kaushik():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('kaushik.html', req=req)

@app.route("/rituparna")
@login_required
def rituparna():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('rituparna.html', req=req)

@app.route("/arif")
@login_required
def arif():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('arif.html', req=req)

@app.route("/ritik")
@login_required
def ritik():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('ritik.html', req=req)

@app.route("/siddharth_ghosh")
@login_required
def siddharth_ghosh():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('siddharth_ghosh.html', req=req)

@app.route("/adarsh")
@login_required
def adarsh():
    s = users.select().where(users.c.id == session['user_id'])
    result = conn.execute(s)
    for row in result:
        req = row[3]
    return render_template('adarsh.html', req=req)

@app.route("/study_materials")
def study_materials():
    return render_template('study_materials.html')

@app.route("/messages")
@login_required
def messages():
    s = ms.select()
    messages = conn.execute(s)
    msgs = []
    for message in messages:
        msgs.append(message)
    msgs.reverse()
    loop = len(msgs)
    return render_template('messages.html', req=1, loop=loop, msgs=msgs)
