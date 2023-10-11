from run import app
from flask import render_template, make_response, redirect
#from flask_login import login_user, logout_user, login_required, current_user
@app.route('/')
def index():
    ref = make_response(render_template('index.html',),200)
    return ref

@app.route('/jwt')
def index_jwt():
    ref = make_response(render_template('index_jwt.html',),200)
    return ref

@app.route('/session')
def index_session():
    ref = make_response(render_template('index_session.html',),200)
    return ref