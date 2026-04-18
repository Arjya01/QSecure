"""
Q-Secure | backend/extensions.py
Flask extension singletons.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt

db      = SQLAlchemy()
jwt     = JWTManager()
cors    = CORS()
limiter = Limiter(key_func=get_remote_address)
bcrypt  = Bcrypt()
