from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'full_name' not in session:
            return jsonify({'message': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    full_name = data.get('full_name')
    password = data.get('password')

    if not email or not full_name or not password:
        return jsonify({'message': 'Missing email, full name, or password'}), 400

    user_with_same_email = User.query.filter(User.email == email).first()

    if user_with_same_email:
        return jsonify({'message': 'Email already exists'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_user = User(email=email, full_name=full_name, password=hashed_password)
    db.session.add(new_user)
    
    try:
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error creating user', 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')  
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing email or password'}), 400

    user = User.query.filter_by(email=email).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
        session['full_name'] = user.full_name  
        session['user_id'] = user.id
        session['email'] = user.email 
        return jsonify({
            'message': 'Logged in successfully',
            'full_name': user.full_name,
            'email': user.email,
            'user_id': user.id
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.pop('full_name', None)
    session.pop('user_id', None)
    session.pop('email', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/user', methods=['GET'])
@login_required
def get_user():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if user:
        return jsonify({
            'user_id': user.id,
            'full_name': user.full_name,
            'email': user.email
        }), 200
    else:
        return jsonify({'message': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)