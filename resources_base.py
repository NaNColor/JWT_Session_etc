from flask_restful import Resource
from models import UserModel
from flask import render_template, make_response, redirect, Flask, request, flash
from run import app
import base64

@app.route('/ba')
def index_base():
    ref = make_response(render_template('index_base.html',),200)
    return ref


@app.route('/ba/login',methods = ['POST', 'GET'])
def login_base():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = UserModel.find_by_username(username)

        if not user:
            return make_response(render_template('login_base.html', myerror='User {} doesn\'t exist'.format(username)),200 )
        if not UserModel.verify_hash(password, user.password):
            return make_response(render_template('login_base.html', myerror='Wrong password'),200 )

        res = make_response(render_template('login_base2.html', myerror='0'), 200)
        encoded = base64.b64encode((username + ':' + password).encode('ascii')).decode('ascii')
        res.set_cookie('Auth', encoded, 60*60*5)
        
        return res

    else:
        if not request.cookies.get('Auth'):
            return make_response(render_template('login_base.html', myerror='0'),200 )
        else:
            flash('You alredy authorized')
            return redirect("/ba/base")

@app.route('/ba/logout',methods = ['POST', 'GET'])
def logout_base():
    if request.method != 'POST':
        if not request.cookies.get('Auth'):
            flash('You have not authorized')
            return redirect("/ba")
        res = make_response(render_template('logout_base.html', myerror='0'),200 )
    else:
        if not request.cookies.get('Auth'):
            flash('You have not authorized')
            return redirect("/ba")
        else:
            res = make_response(render_template('logout_base2.html', myerror='0'),200 )
            res.set_cookie('Auth', '', expires=0)
    return res

class UserBase_base(Resource):
    def get(self):
        cookies = request.cookies.get('Auth')
        if not cookies:
            flash('You have not authorized')
            return redirect("/ba/login")
        user_data =  base64.b64decode(cookies.encode('ascii')).decode('ascii')
        if user_data.find(':') == -1:
            flash('Your authorization was ended')
            return redirect("/ba/login")
        else:
            username = user_data.split(':')[0]
            user = UserModel.find_by_username(username)
            if not user:
                flash('Your authorization was crashed')
                return redirect("/ba/login")
            password = user_data.split(':')[1]
            if not UserModel.verify_hash(password, user.password):
                flash('Your authorization was crashed')
                return redirect("/ba/login")
        return make_response(render_template('base.html', name = username),200 )