"""
Q-Secure | backend/config.py
Environment-based configuration.
"""
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "qsecure-dev-secret-change-in-prod")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///qsecure.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "qsecure-jwt-dev-secret")
    JWT_ACCESS_TOKEN_EXPIRES  = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_TOKEN_LOCATION = ["headers", "query_string"]

    CORS_ORIGINS = "*"

    RATELIMIT_DEFAULT         = "200 per minute"
    RATELIMIT_STORAGE_URL     = "memory://"

    SCANNER_MOCK_MODE = os.environ.get("SCANNER_MOCK_MODE", "false").lower() == "true"

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "postgresql://qsecure:qsecure@db:5432/qsecure")

config_map = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
}
