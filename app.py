# Import required libraries
import os
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
from dotenv import load_dotenv

# Load settings from .env
load_dotenv()

# Setup the Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')

# Setup extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

JWT_SECRET = os.getenv('JWT_SECRET')
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_HOURS = 24

# Create User model (table)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    @property
    def password(self):
        raise AttributeError("Password is write-only.")

    @password.setter
    def password(self, pw):
        self.password_hash = bcrypt.generate_password_hash(pw).decode()

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password_hash, pw)

# Generate JWT token
def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXP_DELTA_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Protect routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        hdr = request.headers.get('Authorization', None)
        if hdr and hdr.startswith('Bearer '):
            token = hdr.split()[1]
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user = User.query.get(data['user_id'])
        except Exception:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Routes

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already taken'}), 400
    user = User(username=data['username'])
    user.password = data['password']
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid username or password'}), 401
    token = generate_jwt(user.id)
    return jsonify({'token': token}), 200

@app.route('/api/dashboard', methods=['GET'])
@token_required
def dashboard(current_user):
    return jsonify({'message': f'Welcome {current_user.username}! This is your dashboard.'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # <-- now inside app context!
    app.run(port=5000)

