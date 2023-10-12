from flask_restful import Resource
from models import UserModel, APIkeysModel
from flask import render_template, make_response, redirect, Flask, request, flash
from run import app
import random, string, requests
import base64

@app.route('/api-keys', methods = ['POST', 'GET'])
def index_apikeys():
    if request.method == 'POST':
        apikey=request.form['apikey']
        x = requests.get(f'https://127.0.0.1:5000/api-keys/api/v1/check?apikey={apikey}', verify=False)
        flash(f'The user {x.text} owns the API-Key {apikey}')

    ref = make_response(render_template('index_api-keys.html'), 200)
    return ref


@app.route('/api-keys/generate',methods = ['POST', 'GET'])
def generate_apikeys():
    if request.method == 'POST':
        username=request.form['username']
        user = UserModel.find_by_username(username)
        if not user:
            flash(f'No such user: {username}')
        else:
            new_apikey = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
            new_user_apikey = APIkeysModel(
            	apikey = new_apikey,
                username = username
            )
            new_user_apikey.save_to_db()

            flash(f'API-Key for user {username} is: {new_apikey}')

    return make_response(render_template('generate_api-keys.html'), 200)

@app.route('/api-keys/api/v1/check')
def check_apikeys():
    apikey = request.args.get('apikey')
    if not apikey:
        return ''
    if request.method == 'GET':
        user = APIkeysModel.find_by_apikey(apikey).username
        if not user:
            return ''

        return user
