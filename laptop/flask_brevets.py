#!/usr/bin/env python
"""
Replacement for RUSA ACP brevet time calculator
(see https://rusa.org/octime_acp.html)

"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from urllib.parse import urlparse, urljoin
from flask import request, redirect, url_for, render_template, Flask, jsonify, session, flash
from flask_restful import Resource, Api
from flask_login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin,
                            confirm_login, fresh_login_required)

from itsdangerous import (TimedJSONWebSignatureSerializer \
                                  as Serializer, BadSignature, \
                                  SignatureExpired)

from passlib.apps import custom_app_context as pwd_context
from pymongo import MongoClient
import arrow  # Replacement for datetime, based on moment.js
import acp_times  # Brevet time calculations
import logging
import time
import os

###
# Classes and Functions
###
class User(UserMixin):
    def __init__(self, name, id, active=True):
        self.name = name
        self.id = id
        self.active = active

    def is_active(self):
        return self.active

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

def hash_password(password):
    return pwd_context.encrypt(password)

def verify_password(password, hashVal):
    return pwd_context.verify(password, hashVal)

def generate_auth_token(expiration=600):
   # s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
   s = Serializer('test1234@#$', expires_in=expiration)
   # pass index of user
   return s.dumps({'id': 1})

def verify_auth_token(token):
    s = Serializer('test1234@#$')
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None    # valid token, but expired
    except BadSignature:
        return None    # invalid token
    return "Success"

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

###
# Globals
###
app = Flask(__name__)
app.config['SECRET_KEY'] = "shhhhh it is a secret"
api = Api(app)
client = MongoClient("172.21.0.2", 27017)
db = client.brevetsdb
dbu = client.usersdb

login_manager = LoginManager()
login_manager.setup_app(app)

login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"

USERS = {
    1: User(u"A", 1),
    2: User(u"B", 2),
}
USER_NAMES = dict((u.name, u) for u in USERS.values())

@login_manager.user_loader
def load_user(id):
    return USERS.get(int(id))
'''
@login_manager.user_loader
def load_user(id):
    return db.userdb.find({"id" : id })
'''

###
# Pages
###
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():

        username = form.username.data
        remember = form.remember_me.data

        if username in USER_NAMES:

            if login_user(USER_NAMES[username], remember=remember):

                flash("Logged in!")
                next = request.args.get('next')

                if not is_safe_url(next):
                    return flask.abort(400)
                return redirect(request.args.get("next") or url_for("index"))
            else:
                flash("Sorry, but you could not log in.")
        else:
            flash(u"Invalid username.")
    return render_template('login.html',  title='Sign In', form=form)

@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash(u"Reauthenticated.")
        if not is_safe_url(next):
            return flask.abort(400)
        return redirect(request.args.get("next") or url_for("index"))
    return render_template("reauth.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))

@app.route("/")
@app.route("/index")
def index():
    app.logger.debug("Main page entry")
    return render_template('calc.html'), 200

@app.route("/<filepath>")
def found(filepath):
    if ((".." in filepath) or ("//" in filepath) or ("~" in filepath)):
        return render_template('403.html'), 403
    if os.path.isfile("templates/" + filepath):
        return render_template(filepath), 200
    else:
        return render_template('404.html'), 404

@app.route("/display")
@login_required
def display():
    app.logger.debug("Display page entry")
    _times = db.brevetsdb.find().sort( "dist", 1)
    times = [time for time in _times]
    db.brevetsdb.remove({})
    return render_template('display.html', times=times), 200

###
# AJAX request handlers
###
@app.route("/_calc_times")
def _calc_times():
    """
    Calculates open/close times from miles, using rules
    described at https://rusa.org/octime_alg.html.
    Expects one URL-encoded argument, the number of miles.
    """
    app.logger.debug("Got a JSON request: Calculate Times")
    km = request.args.get('km', 999, type=float)
    date = request.args.get('dt', type=str)
    brev = request.args.get('bv', type=float)
    open_time = acp_times.open_time(km, brev, date)
    close_time = acp_times.close_time(km, brev, date)
    result = {"open": open_time, "close": close_time}
    return jsonify(result=result)

@app.route("/_submit")
def submit():
    """
    Adds an ACP-sanctioned brevet to database
    if it doesn't already exist
    """
    app.logger.debug("Got a JSON request: Submit")
    distance = float(request.args.get("d"))
    name = request.args.get("n")
    openTime = request.args.get("o")
    closeTime = request.args.get("c")
    time_doc = {
        "dist": distance,
        "nm": name,
        "op": openTime,
        "cl": closeTime
    }
    db.brevetsdb.update({ "dist": distance }, time_doc, True);
    return jsonify()

###
# Error Handlers
###
@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    session['linkback'] = flask.url_for("index")
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden_request(error):
    app.logger.debug("Forbidden request")
    session['linkback'] = flask.url_for("index")
    return render_template('403.html'), 403

###
# Api
###
class listAll(Resource):
    def get(self):
        _times = db.brevetsdb.find().sort( "dist", 1)
        times = [time for time in _times]
        time_array = []
        for item in times:
            time_array.append("Open: " + item["op"] + " Close: " + item["cl"])

        return { 'Times' : time_array}

class listAllj(Resource):
    def get(self):
        _times = db.brevetsdb.find().sort( "dist", 1)
        times = [time for time in _times]
        time_array = []
        for item in times:
            time_array.append("Open: " + item["op"] + " Close: " + item["cl"])

        return { 'Times' : time_array}

class listAllc(Resource):
    def get(self):
        _times = db.brevetsdb.find().sort( "dist", 1)
        times = [time for time in _times]
        all = ""
        for item in times:
            all += "Open: " + item["op"] + " Close: " + item["cl"] +","
        all = all[:-1]
        return all

class listOpenOnly(Resource):
    def get(self):
        _times = db.brevetsdb.find().sort( "dist", 1)
        times = [time for time in _times]
        open_time_array = []
        for item in times:
            open_time_array.append(item["op"])
        return { 'openTime' : open_time_array}

class listOpenOnlyj(Resource):
    def get(self):
        topp = request.args.get("top")
        if topp == None:
            topp = 0
        _times = db.brevetsdb.find().sort( "dist", 1).limit(int(topp))
        times = [time for time in _times]
        open_time_array = []
        for item in times:
            open_time_array.append(item["op"])
        return { 'openTime' : open_time_array}

class listOpenOnlyc(Resource):
    def get(self):
        topp = request.args.get("top")
        if topp == None:
            topp = 0
        _times = db.brevetsdb.find().sort( "dist", 1).limit(int(topp))
        times = [time for time in _times]
        opentimes = ""
        for item in times:
            opentimes += item["op"] + ","
        opentimes = opentimes[:-1]
        return opentimes

class listCloseOnly(Resource):
    def get(self):
        _times = db.brevetsdb.find().sort( "dist", 1)
        times = [time for time in _times]
        close_time_array = []
        for item in times:
            close_time_array.append(item["cl"])
        return { 'closeTime' : close_time_array}

class listCloseOnlyj(Resource):
    def get(self):
        topp = request.args.get("top")
        if topp == None:
            topp = 0
        _times = db.brevetsdb.find().sort( "dist", 1).limit(int(topp))
        times = [time for time in _times]
        close_time_array = []
        for item in times:
            close_time_array.append(item["cl"])
        return { 'closeTime' : close_time_array}

class listCloseOnlyc(Resource):
    def get(self):
        topp = request.args.get("top")
        if topp == None:
            topp = 0
        _times = db.brevetsdb.find().sort( "dist", 1).limit(int(topp))
        times = [time for time in _times]
        closetimes = ""
        for item in times:
            closetimes += item["cl"] + ","
        closetimes = closetimes[:-1]
        return closetimes


api.add_resource(listAll, '/listAll')
api.add_resource(listAllj, '/listAll/json')
api.add_resource(listAllc, '/listAll/csv')
api.add_resource(listOpenOnly, '/listOpenOnly')
api.add_resource(listOpenOnlyj, '/listOpenOnly/json')
api.add_resource(listOpenOnlyc, '/listOpenOnly/csv')
api.add_resource(listCloseOnly, '/listCloseOnly')
api.add_resource(listCloseOnlyj, '/listCloseOnly/json')
api.add_resource(listCloseOnlyc, '/listCloseOnly/csv')

###############

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
