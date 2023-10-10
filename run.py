from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

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


import views, models, resources

with app.app_context():
    db.create_all()

api = Api(app)

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin_jwt, '/login_jwt')
#api.add_resource(resources.UserLogoutAccess, '/logout_jwt/access')
#api.add_resource(resources.UserLogoutRefresh, '/logout_jwt/refresh')
#api.add_resource(resources.TokenRefresh, '/token_jwt/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.SecretResource_jwt, '/secret_jwt')


