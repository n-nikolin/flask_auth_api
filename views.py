# IF I FUCK - PUT BACK IN api FOLDER


from . import db, bcrypt
from .models import Person
from .config import Config

from functools import wraps
import jwt
import uuid
import re

from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, jsonify, request, make_response

main = Blueprint('main', __name__)

def token_requiered(f):
    # make decorator that checks if token exists
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(
                token, Config.SECRET_KEY, algorithms=['HS256'])
            current_user = Person.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# TOKEN STUFF
def token_refresh():
    # a function that automatically refreshes token
    pass

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

# AUTH STUFF
@main.route('/register', methods=['POST'])
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


@main.route('/login', methods=['GET', 'POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        print('not auth or not auth.username or not auth.password')
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

    # prefer using email to log in, so in Postman 'username' field input email instead
    person = Person.query.filter_by(email=auth.username).first()

    if not person:
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

    if check_password_hash(person.password, auth.password):
        token = jwt.encode(
            {'public_id': person.public_id,
            'exp': datetime.now()+timedelta(minutes=30)},
            Config.SECRET_KEY
        )

        return jsonify({'token': token}), 200

    return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

@main.route('/logout', methods = ['POST'])
def logout():
    # logout functionality here
    # delete user access token or some shit
    
    # i was desperate
    token = request.headers['x-access-token']
    make_expired_token = jwt.decode(
    token, Config.SECRET_KEY, algorithms=['HS256'])
    return jsonify(make_expired_token)

    pass

@main.route('/<public_id>/dashboard', methods = ['GET'])
@token_requiered
def user_dashboard(current_user, public_id):
    # if user is logged in show this page
    person = Person.query.filter_by(public_id=current_user.public_id).first()
    if not person:
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )
    
    output = {
        'username': person.username,
        'id': person.id,
        'email': person.email
    }
    
    return jsonify(output), 200

@main.route('/<public_id>/update_profile', methods= ['PUT'])
@token_requiered
def update_profile(current_user, public_id):
    # update user credentials (email, password, username)
    person = Person.query.filter_by(public_id=current_user.public_id).first()
    
    if not person:
        return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

    data = request.get_json()
    
    # TEST THIS OUT!!!
    # if data.keys() != '':
    #     person.username = data['username']
    #     if is_email(data['email']):
    #         person.email = data['email']
    #     else:
    #         return jsonify({'message': 'invalid email!'}), 401
    #     if is_strong_password(data['password']):
    #         person.password = generate_password_hash(data['password'], method='sha256')
    #     else:
    #         return jsonify({'message': 'weak password!'}), 401
    
    # THIS WORKS BUT DOESN'T LOOK NICE
    if data['usermane'] != '':
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