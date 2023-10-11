from flask_restful import Resource
from models import UserModel, OTPModel
from flask import render_template, make_response, redirect, Flask, request, flash
from run import app
import random, string
import base64

@app.route('/otp', methods = ['POST', 'GET'])
def index_otp():
    if request.method == 'POST':
        username=request.form['username']
        user = UserModel.find_by_username(username)
        if not user:
            flash(f'No such user: {username}')
        else:
            cur_otp = OTPModel.find_by_username(username)
            new_otp = ''.join(random.choice(string.digits) for _ in range(6))
            if not cur_otp:
                new_user_otp = OTPModel(
                    username = username,
                    otp = new_otp
                )
                new_user_otp.save_to_db()
            else:
                OTPModel.change_otp(username, new_otp)

            flash(f'OTP for user {username} is: {new_otp}')

    ref = make_response(render_template('index_otp.html'), 200)
    return ref

@app.route('/mfa')
def index_mfa():
    ref = make_response(render_template('index_mfa.html'),200)
    return ref


@app.route('/mfa/login',methods = ['POST', 'GET'])
def login_mfa():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = UserModel.find_by_username(username)

        if not user:
            return make_response(render_template('login_mfa.html', myerror='User {} doesn\'t exist'.format(username)),200 )
        if not UserModel.verify_hash(password, user.password):
            return make_response(render_template('login_mfa.html', myerror='Wrong password'), 200)

        return redirect(f"/mfa/otp?user={username}")

    else:
        if not request.cookies.get('mfa'):
            return make_response(render_template('login_mfa.html', myerror='0'),200)
        else:
            flash('You alredy authorized')
            return redirect("/mfa/profile")

@app.route('/mfa/otp',methods = ['POST', 'GET'])
def otp_mfa():
    username = request.args.get('user')
    if not username:
        return redirect("/mfa/login")
    if request.method == 'POST':
        otp=request.form['otp']
        user = UserModel.find_by_username(username)
        if not user:
            return make_response(render_template('login_mfa.html', myerror='User {} doesn\'t exist'.format(username)),200 )

        cur_otp = OTPModel.find_by_username(username).otp
        if cur_otp != otp:
            flash(f'{cur_otp} != {otp}')
            return redirect(f"/mfa/otp?user={username}")
        else:
            res = make_response(render_template('login_mfa2.html', myerror='0'), 200)
            encoded = base64.b64encode((username).encode('ascii')).decode('ascii')
            res.set_cookie('mfa', encoded, 60*60*5)

            return res

    else:
        if not request.cookies.get('mfa'):
            return make_response(render_template('otp_mfa.html', username=username), 200)
        else:
            flash('You alredy authorized')
            return redirect("/mfa/profile")

@app.route('/mfa/logout',methods = ['POST', 'GET'])
def logout_mfa():
    if request.method == 'GET':
        if not request.cookies.get('mfa'):
            flash('You have not authorized')
            return redirect("/mfa")
        res = make_response(render_template('logout_mfa.html', myerror='0'), 200)
    else:
        if not request.cookies.get('mfa'):
            flash('You have not authorized')
            return redirect("/mfa")
        else:
            res = make_response(render_template('logout_mfa2.html', myerror='0'),200 )
            res.set_cookie('mfa', '', expires=0)
    return res

@app.route('/mfa/profile')
def profile_mfa():
    cookies = request.cookies.get('mfa')
    if not cookies:
        flash('You have not authorized')
        return redirect("/mfa/login")
    user_data =  base64.b64decode(cookies.encode('ascii')).decode('ascii')
    username = user_data
    user = UserModel.find_by_username(username)
    if not user:
        flash('Your authorization was crashed')
        return redirect("/mfa/login")
    return make_response(render_template('profile_mfa.html', name = username), 200)
