from . import db

class Person(db.Model):
    __tablename__ = 'person'
    id = db.Column(db.Integer, primary_key=True, nullable=False, unique=True)
    public_id = db.Column(db.String(50), nullable=False, unique=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(88), unique=False)

class TokenBlockList(db.Model):
    __tablename__ = 'token_blocked_list'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)