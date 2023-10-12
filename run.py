from flask import Flask, Blueprint
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_login import LoginManager

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = '8e977ef74bf745ac153c117a2c9e76c6'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blocklisted(jti)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '8e977ef74bf745ac153c117a2c9e76c6'



db = SQLAlchemy(app)


import views, models, resources_jwt, resources_session, resources_base, resources_mfa, resources_apikeys

from models import UserModel
login_manager = LoginManager()
login_manager.login_view = '/session/login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return UserModel.query.get(int(user_id))

with app.app_context():
    db.create_all()

api = Api(app)

api.add_resource(resources_jwt.UserRegistration, '/registration')
api.add_resource(resources_jwt.UserLogin_jwt, '/jwt/login')
api.add_resource(resources_jwt.AllUsers, '/users')
api.add_resource(resources_jwt.SecretResource_jwt, '/jwt/profile')
api.add_resource(resources_session.UserLogin_session, '/session/login')




#api.add_resource(resources_base.UserLogin_base, '/ba/login')
#api.add_resource(resources_base.UserLogout_base, '/ba/logout')
api.add_resource(resources_base.UserBase_base, '/ba/base')

# context = ('server.crt', 'server.key')
# app.run(host='127.0.0.1', ssl_context=context, port=8000,threaded=True, debug=True)# ssl_context=context, 
    #app.run(host='127.0.0.1',debug=True, ssl_context=context)
