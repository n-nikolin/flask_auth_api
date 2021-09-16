from . import db, bcrypt
from . import jwt
from .models import Person, TokenBlockList

import uuid
import re
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, jsonify, request, make_response

from flask_jwt_extended import create_access_token, get_jwt_identity, get_jwt
from flask_jwt_extended.utils import create_refresh_token, get_jwt_header
from flask_jwt_extended.view_decorators import jwt_required

main = Blueprint('main', __name__)

# INPUT VALIDATION
def is_strong_password(password):
    # checks if password is strong
    lower_regex = re.compile(r'[a-z]')
    upper_regex = re.compile(r'[A-Z]')
    number_regex = re.compile(r'[0-9]')
    #THIS IS SHIT AND THERE IS A BETTER WAY OF DOING THIS
    if lower_regex.search(password) and upper_regex.search(password) and number_regex.search(password) and len(password)>=8:
        return True
    else:
        return False

def is_email(email):
    # checks if string is email
    email_regex = re.compile(r'''(
        [a-zA-z0-9._%+-]+   # username
        @                   # @ symbol
        [a-zA-Z0-9.-]+      # domain name
        (\.[a-zA-Z]{2,4})   # dot something
        )''', re.VERBOSE
    )
    if email_regex.search(email):
        return True
    else:
        return False

# TOKEN STUFF
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlockList.query.filter_by(jti=jti).scalar()
    return token is not None

# AUTH STUFF
@main.route('/api/auth/register', methods=['POST'])
def register():
    # registers new user
    # refactor this shit - too much repetitive code
    data = request.get_json()
    if is_strong_password(data['password']) and is_email(data['email']):
        print('yep')
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = Person(
                public_id=str(uuid.uuid4()),
                username=data['username'],
                email=data['email'],
                password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'New user created!'}), 200
    else:
        if not is_strong_password(data['password']) and is_email(data['email']):
            print('not password')
            return jsonify({'message': 'Weak password!'}), 400
        if not is_email(data['email']) and is_strong_password(data['password']):
            print('not email')
            return jsonify({'message': 'Invalid email!'}), 400

@main.route('/api/auth/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        print('1')
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

    # prefer using email to log in, so in Postman 'username' field input email instead
    person = Person.query.filter_by(email=auth.username).first()

    if not person:
        print('2')
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

    if check_password_hash(person.password, auth.password):
        access_token = create_access_token(identity=person.public_id, fresh=True)
        refresh_token = create_refresh_token(identity=person.public_id)
        return jsonify(access_token=access_token, refresh_token=refresh_token)

    return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}, {'msg': '3'}
        )

@main.route('/api/token/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, fresh=False)
    return jsonify(access_token=access_token)

@main.route('/api/auth/logout', methods = ['DELETE'])
@jwt_required()
def logout():
    # insert logout stuff here
    # this doesn't seem to work and i don't know why
    jti = get_jwt()['jti']
    now = datetime.now()
    db.session.add(TokenBlockList(jti=jti, created_at=now))
    db.session.commit()
    return jsonify(msg='You have logged out! JWT REVOKED'), 200

# USER STUFF
@main.route('/api/<public_id>/dashboard', methods = ['GET'])
@jwt_required()
def user_dashboard(public_id):
    # if user is logged in show this page
    person = Person.query.filter_by(public_id=get_jwt_identity()).first()
    if not person:
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )
    
    output = {
        'username': person.username,
        'email': person.email
    }
    
    return jsonify(output), 200

@main.route('/api/<public_id>/update_profile', methods= ['PUT'])
@jwt_required()
def update_profile(public_id):
    # update user credentials (email, password, username)
    person = Person.query.filter_by(public_id=get_jwt_identity()).first()
    
    if not person:
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

    data = request.get_json()

    # THIS WORKS BUT DOESN'T LOOK NICE           
    if data['username'] != '':
        person.username = data['username']
    
    if data['email'] != '' and is_email(data['email']):
        person.email = data['email']
    else:
        return jsonify({'message': 'invalid email!'}), 401

    if data['password'] != '' and is_strong_password(data['password']):
        person.password = generate_password_hash(data['password'], method='sha256')
    else:
        return jsonify({'message': 'weak password!'}), 401

    db.session.commit()

    update_profile_data = {
        'username': data['username'],
        'email': data['email'],
        'password': '*'*8
    }

    return jsonify(update_profile_data), 200