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

# CHECK IF STRONG PASSWORD
def is_strong_password(password):
    # checks if password is strong
    lower_regex = re.compile(r'[a-z]')
    upper_regex = re.compile(r'[A-Z]')
    number_regex = re.compile(r'[0-9]')
    #THIS IS SHIT AND THERE IS A BETTER WAY OF DOING THIS
    if lower_regex.search(password) and upper_regex.search(password) and number_regex.search(password) and len(password)>=8:
        # return status 201 OK
        True
    else:
        # return error - shit password
        False

def is_email(email):
    email_regex = re.compile(r'''(
        [a-zA-z0-9._%+-]+   # username
        @                   # @ symbol
        [a-zA-Z0-9.-]+      # domain name
        (\.[a-zA-Z]{2,4})   # dot something
        )''', re.VERBOSE
    )
    if email_regex.search(email):
        True
    else:
        False

# AUTH STUFF
@main.route('/register', methods=['POST'])
def register():
    #registers new user
    data = request.get_json()
    print(data)
    # if is_strong_password(data['password']) and is_email(data['email']):
    if is_strong_password(data['password']):
        print(data['password'])
        print('strong password')
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = Person(
            public_id=str(uuid.uuid4()),
            username=data['username'],
            email=data['email'],
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'New user created!'})
    else:
        return jsonify({'message': 'Weak password!'})
        # if not is_email(data['email'])==False:
        #     return jsonify({'message': 'Invalid email'})
        # if not is_strong_password(data['password']):
        #     return jsonify({'message': 'Weak password!'})
    

@main.route('/login', methods=['GET', 'POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
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

        return jsonify({'token': token})

    return make_response(
            'Could not verify', 401,
            {'WWW-Authenticate': 'Basic realm = "Login required!"'}
        )

@main.route('/logout', methods = ['POST'])
def logout():
    # logout functionality here
    # delete user access token

    pass

@main.route('/<public_id>/dashboard', methods = ['GET'])
@token_requiered
def user_dashboard(current_user, public_id):
    # if user is logged in show this page
    person = Person.query.filter_by(public_id=current_user.public_id).first()
    output = {
        'username': person.username,
        'id': person.id,
        'email': person.email
    }
    return jsonify({'data': f'hey {output}'})

@main.route('/<public_id>/update_account', methods= ['POST'])
@token_requiered
def update_user_credentials():
    # update user credentials (email, password, username)
    pass