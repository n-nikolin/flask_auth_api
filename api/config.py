from datetime import timedelta

# Development settings
class Config:
    # APP
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:1234@localhost/flask_react_auth'
    SECRET_KEY = 'secret'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # FLASK_JWT_EXTENDED
    JWT_SECRET_KEY = 'kinda-secret'
    JWT_TOKEN_LOCATION = 'headers'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

