from run import app
from flask import jsonify, render_template, make_response, redirect
from flask_login import login_user, logout_user, login_required, current_user
@app.route('/')
def index():
    ref = make_response(render_template('index.html',),200)
    return ref


@app.route('/logout')
@login_required
def logout():
    logout_user()
    resp.set_cookie('sessionID', '', expires=0)
    return redirect("/login_session")
@app.route('/profile')
@login_required
def login():
    return render_template('profile.html', name=current_user.username)