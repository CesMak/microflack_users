import os
import threading
import time
import logging

from flask import Flask, jsonify, request, abort, g, session
from flask_httpauth import HTTPBasicAuth
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash

import config
from microflack_common.auth import token_auth, token_optional_auth
from microflack_common.utils import timestamp, url_for
from microflack_common import requests
import base64

logging.basicConfig(level=logging.WARNING, format='[%(funcName)10s()-%(lineno)s:] %(message)s')
# logging works like this:
# logging.info("inside /api/users/me.....")
# logging.warning("inside /api/users/me.....")
# logging.error("inside /api/users/me.....")
# logging.critical("inside /api/users/me.....")

app = Flask(__name__)
config_name = os.environ.get('FLASK_CONFIG', 'dev')
app.config.from_object(getattr(config, config_name.title() + 'Config'))

db         = SQLAlchemy(app)
migrate    = Migrate(app, db)
basic_auth = HTTPBasicAuth()

message_queue = 'redis://' + os.environ['REDIS'] if 'REDIS' in os.environ \
    else None
if message_queue:
    socketio = SocketIO(message_queue=message_queue)
else:
    socketio = None


@basic_auth.verify_password
def verify_password(nickname, password):
    """Password verification callback."""
    if not nickname or not password:
        return False
    user = User.query.filter_by(nickname=nickname).first()
    if user is None or not user.verify_password(password):
        return False
    user.ping()
    db.session.commit()
    g.current_user = user
    return True


@basic_auth.error_handler
def password_error():
    """Return a 401 error to the client."""
    # To avoid login prompts in the browser, use the "Bearer" realm.
    return (jsonify({'error': 'authentication required'}), 401,
            {'WWW-Authenticate': 'Bearer realm="Authentication Required"'})


class User(db.Model):
    """The User model."""
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    created_at    = db.Column(db.Integer, default=timestamp)
    updated_at    = db.Column(db.Integer, default=timestamp, onupdate=timestamp)
    last_seen_at  = db.Column(db.Integer, default=timestamp)
    nickname      = db.Column(db.String(32), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    online        = db.Column(db.Boolean, default=False)
    roomid        = db.Column(db.Integer, nullable=False, default=0)
    sid           = db.Column(db.String(256), nullable=False, default="")

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def ping(self):
        """Marks the user as recently seen and online."""
        self.last_seen_at = timestamp()
        self.online = True

    @staticmethod
    def create(data):
        """Create a new user."""
        user = User()
        user.from_dict(data, partial_update=False)
        return user

    def from_dict(self, data, partial_update=True):
        """Import user data from a dictionary. Converts model to representation (for api)
        Note a request must contain at least these fields nickname,.... sid"""
        for field in ['nickname', 'password', 'roomid', 'sid']:
            try:
                setattr(self, field, data[field])
            except KeyError:
                if not partial_update:
                    abort(400)

    def to_dict(self):
        """Export user to a dictionary. links are build e.g. /api/messages/{}"""
        return {
            'id': self.id,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'nickname': self.nickname,
            'roomid': self.roomid,
            'sid': self.sid,
            'last_seen_at': self.last_seen_at,
            'online': self.online,
            '_links': {
                'self': url_for('get_user', id=self.id),
                'messages': '/api/messages/{}'.format(self.id),
                'tokens': '/api/tokens'
            }
        }

    @staticmethod
    def find_offline_users():
        """Find users that haven't been active and mark them as offline."""
        users = User.query.filter(User.last_seen_at < timestamp() - 60,
                                  User.online == True).all()  # noqa
        for user in users:
            user.online = False
            db.session.add(user)
        db.session.commit()

@db.event.listens_for(User, 'after_insert')
@db.event.listens_for(User, 'after_update')
def after_user_update(mapper, connection, target):
    if socketio is not None:
        socketio.emit('updated_model', {'class': target.__class__.__name__,
                                        'model': target.to_dict()})


@app.before_first_request
def before_first_request():
    """Start a background thread that looks for users that leave."""
    def find_offline_users():
        with app.app_context():
            while True:
                User.find_offline_users()
                db.session.remove()
                time.sleep(5)

    if not app.config['TESTING']:
        thread = threading.Thread(target=find_offline_users)
        thread.start()


@app.before_request
def before_request():
    if hasattr(g, 'jwt_claims') and 'user_id' in g.jwt_claims:
        user = User.query.get(g.jwt_claims['user_id'])
        if user is None:
            abort(500)
        user.ping()
        db.session.add(user)
        db.session.commit()


@app.route('/api/users', methods=['POST'])
def new_user():
    """
    Register a new user.
    This endpoint is publicly available.
    """
    user = User.create(request.get_json() or {})
    if User.query.filter_by(nickname=user.nickname).first() is not None:
        abort(400)
    db.session.add(user)
    db.session.commit()
    r = jsonify(user.to_dict())
    r.status_code = 201
    r.headers['Location'] = url_for('get_user', id=user.id)
    return r


@app.route('/api/users', methods=['GET'])
@token_optional_auth.login_required
def get_users():
    """
    Return list of users.
    This endpoint is publicly available, but if the client has a token it
    should send it, as that indicates to the server that the user is online.
    """
    users = User.query.order_by(User.updated_at.asc(), User.nickname.asc())
    if request.args.get('online'):
        users = users.filter_by(online=(request.args.get('online') != '0'))
    if request.args.get('updated_since'):
        users = users.filter(
            User.updated_at >= int(request.args.get('updated_since')))
    # users=SELECT users.id AS users_id, users.created_at AS users_created_at, users.updated_at AS users_updated_at, users.last_seen_at AS users_last_seen_at, users.nickname AS users_nickname, users.password_hash AS users_password_hash, users.online AS users_online, users.roomid AS users_roomid, users.sid AS users_sid
    #       FROM users
    #       WHERE users.updated_at >= %(updated_at_1)s ORDER BY users.updated_at ASC, users.nickname ASC
    # for i in users.all():
    #     print(i)
    #     print(i.to_dict())
    return jsonify({'users': [user.to_dict() for user in users.all()]})


@app.route('/api/users/<int:id>', methods=['GET'])
@token_optional_auth.login_required
def get_user(id):
    """
    Return a user.
    This endpoint is publicly available, but if the client has a token it
    should send it, as that indicates to the server that the user is online.
    """
    return jsonify(User.query.get_or_404(id).to_dict())


@app.route('/api/users/<int:id>', methods=['PUT'])
@token_auth.login_required
def edit_user(id):
    """
    Modify an existing user.
    This endpoint requires a valid user token.
    Note: users are only allowed to modify themselves.
    sid is empty here as well.
    """
    user = User.query.get_or_404(id)
    if user.id != g.jwt_claims['user_id']:
        abort(403)
    user.from_dict(request.get_json() or {})
    db.session.add(user)
    db.session.commit()
    return '', 204


@app.route('/api/users/me', methods=['GET'])
@basic_auth.login_required
def get_me_user():
    """
    Return the authenticated user.
    This endpoint requires basic auth with nickname and password.
    The user is usually offline here. sid is empty
    This function is called only once after login
    """
    return jsonify(g.current_user.to_dict())


@app.route('/api/users/me', methods=['PUT'])
@token_auth.login_required
def set_user_online():
    """Set the user that owns the token online."""
    user = User.query.get(g.jwt_claims['user_id'])
    socketio.emit('updated_model', {'class': 'Message',
                                    'model': {'source': '', 'html': '<strong>Server: Hello '+str(user.nickname)+' you are pinged!</strong>', 'roomid': user.roomid}}, room=user.sid)
    if user is not None:
        user.ping()
        db.session.commit()
    return '', 204


@app.route('/api/users/me', methods=['DELETE'])
@token_auth.login_required
def set_user_offline():
    """Set the user that owns the token offline."""
    user = User.query.get(g.jwt_claims['user_id'])

    # message to whole room:
    socketio.emit('updated_model', {'class': 'Message',
                                    'model': {'source': '', 'html': '<strong>Server: '+str(user.nickname)+' has left the room.</strong>', 'roomid': user.roomid}}, room=user.roomid)
    if user is not None:
        user.online = False
        user.sid    = ""
        db.session.commit()
    return '', 204


if __name__ == '__main__':
    app.run()
