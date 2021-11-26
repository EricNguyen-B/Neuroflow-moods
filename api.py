from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy, Model
import jwt
import time
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisecret'
db_path = os.path.join(os.path.dirname(__file__), 'login.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI']  = db_uri

db = SQLAlchemy(app)

most_recent_mood_time = time.time()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    streak = db.Column(db.Integer)
    admin = db.Column(db.Boolean)

class Mood(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    timestamp = db.Column(db.String(150))
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['streak'] = user.streak
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['streak'] = user.streak
    user_data['admin'] = user.admin
    return jsonify({'user': user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, streak=0, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The user has been deleted'})

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/mood', methods=['GET'])
@token_required
def get_all_moods(current_user):
    moods = Mood.query.filter_by(user_id=current_user.id).all()
    output = []
    for mood in moods:
        mood_data = {}
        mood_data['id'] = mood.id
        mood_data['text'] = mood.text
        mood_data['timestamp'] = mood.timestamp
        output.append(mood_data)
    return jsonify({'moods': output})

# @app.before_request
# def before(current_user):
#     curr_time = time.time()
#     if (curr_time > most_recent_mood_time) and (curr_time < curr_time + 120):
#         user = User.query.filter_by(user_id=current_user.id).first()
#         user.streak += 1

@app.route('/mood', methods=['POST'])
@token_required
def submit_mood(current_user):
    data = request.get_json()
    new_mood = Mood(text=data['text'], timestamp = datetime.datetime.utcnow(),user_id=current_user.id)
    db.session.add(new_mood)
    db.session.commit()
    return jsonify({'message': "Mood submitted"})

@app.route('/mood/<mood_id>', methods=['DELETE'])
@token_required
def delete_mood(current_user, mood_id):
    return ''

if __name__ == '__main__':
    app.run(debug=True)