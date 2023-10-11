from flask_restful import Resource
from models import UserModel, RevokedTokenModel
from flask import render_template, make_response, redirect, Flask, request
from run import app
from flask_login import login_user, logout_user, login_required, current_user



class UserLogin_session(Resource):
    def post(self):
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = UserModel.find_by_username(username)

        if not user:
            return make_response(render_template('login_session.html', myerror='User {} doesn\'t exist'.format(username)),200 )
        if not UserModel.verify_hash(password, user.password):
            return make_response(render_template('login_session.html', myerror='Wrong password'),200 )


        login_user(user, remember=remember)
        #render_template('profile.html', name=current_user.username)
        return redirect("/profile")

    def get(self):
        return make_response(render_template('login_session.html', myerror='0'),200 )


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