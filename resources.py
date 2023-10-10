from flask_restful import Resource, reqparse
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt) #jwt_refresh_token_required, get_raw_jwt
from models import UserModel, RevokedTokenModel
from flask import render_template, make_response, redirect, Flask, request, current_app
import json
import jwt
parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)

class UserRegistration(Resource):
    def post(self):
        mydict = {"username":request.form.get('username'), "password":request.form.get('password')}
        data_buf = json.dumps(mydict)
        data = json.loads(data_buf)
        #data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return make_response(render_template('reg.html', myerror='User {} already exists'.format(data['username'])),200)
            #return {'message': 'User {} already exists'.format(data['username'])}

        new_user = UserModel(
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )

        try:
            new_user.save_to_db()
            #access_token = create_access_token(identity = data['username'])
            #refresh_token = create_refresh_token(identity = data['username'])
            return make_response(render_template('reg2.html',),200)
            
        except:
            return make_response(render_template('reg.html', myerror="error"),200, headers)


    def get(self):
        #data = parser.parse_args()
        headers = {'Content-Type': 'text/html',
                    'X-Para': 'para is cool'}
        return make_response(render_template('reg.html', myerror="0"),200, headers)
        #return render_template('reg.html', 200)


class UserLogin_jwt(Resource):
    def post(self):
        #data = parser.parse_args()
        mydict = {"username":request.form.get('username'), "password":request.form.get('password')}
        data_buf = json.dumps(mydict)
        data = json.loads(data_buf)

        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return make_response(render_template('login.html', myerror='User {} doesn\'t exist'.format(data['username'])),200 )
        
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            res = make_response(render_template('login2.html',), 200)
            res.set_cookie("Refresh token", refresh_token, 60*60*15)
            res.set_cookie("jwt", access_token, 60*60)
            res.headers['Authorization'] = 'Bearer ' + access_token
            return res
        else:
            return {'message': 'Wrong credentials'}
    def get(self):
        #data = parser.parse_args()
        headers = {'Content-Type': 'text/html',
                    'Authorization': 'Bearer '}
        return make_response(render_template('login.html', myerror="0"),200, headers)


# class UserLogoutAccess(Resource):
#     @jwt_required
#     def post(self):
#         #jti = get_raw_jwt()['jti']
#         jti = get_jwt()['jti']
#         try:
#             revoked_token = RevokedTokenModel(jti = jti)
#             revoked_token.add()
#             return {'message': 'Access token has been revoked'}
#         except:
#             return {'message': 'Something went wrong'}, 500
      

# class UserLogoutRefresh(Resource):
#     #@jwt_refresh_token_required
#     @jwt_required(refresh=True)
#     def post(self):
#         #jti = get_raw_jwt()['jti']
#         jti = get_jwt()['jti']
#         try:
#             revoked_token = RevokedTokenModel(jti = jti)
#             revoked_token.add()
#             return {'message': 'Refresh token has been revoked'}
#         except:
#             return {'message': 'Something went wrong'}, 500
      

# class TokenRefresh(Resource):
#     #@jwt_refresh_token_required
#     @jwt_required(refresh=True)
#     def post(self):
#         current_user = get_jwt_identity()
#         access_token = create_access_token(identity = current_user)
#         return {'access_token': access_token}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()
    
    def delete(self):
        return UserModel.delete_all()


class SecretResource_jwt(Resource):
    #@jwt_required
    def get(self):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        token = request.cookies.get('jwt')
        if not token:
            return make_response(render_template('secret2.html',),200)
        try:
            data=jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            current_user=UserModel.find_by_username(data["sub"])
            if current_user is None:
                return {
                "message": "Invalid Authentication token!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": None,
                "error": str(e)
            }, 500

        return make_response(render_template('secret.html',),200)

