"""Hidden chat routes - not registered with Flask-Smorest (no Swagger docs), not linked anywhere.

Access is controlled by a per-chat bearer token (X-Chat-Token header) returned by /chat/api/join.
The Flask session is deliberately not used: its secret key is hardcoded, so session cookies can be forged.
"""
from datetime import datetime
from flask import Blueprint, request, render_template, jsonify
from vulapp import chat_store

chat_bp = Blueprint('chat', __name__, url_prefix='/chat')


def _client_ip():
    # X-Real-IP is overwritten by Nginx, unlike the first X-Forwarded-For entry, which the client controls
    return request.headers.get('X-Real-IP') or request.remote_addr


def _token():
    return request.headers.get('X-Chat-Token', '')


def _serialize(message):
    return {
        'id': message['id'],
        'ts': message['ts'],
        'datetime': datetime.fromtimestamp(message['ts']).strftime('%Y-%m-%d %H:%M:%S'),
        'ip': message['ip'],
        'text': message['text'],
    }


def _read_key(data):
    key = data.get('key')
    if not isinstance(key, str) or not key.strip() or len(key) > chat_store.MAX_KEY_LENGTH:
        return None
    return key


@chat_bp.after_request
def _private_headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@chat_bp.route('', strict_slashes=False)
def chat_page():
    return render_template('chat.html',
                           max_message_length=chat_store.MAX_MESSAGE_LENGTH,
                           min_password_length=chat_store.MIN_PASSWORD_LENGTH,
                           poll_interval_ms=chat_store.POLL_INTERVAL_SECONDS * 1000,
                           session_max_ms=chat_store.SESSION_MAX_SECONDS * 1000)


@chat_bp.route('/api/check', methods=['POST'])
def check_key():
    key = _read_key(request.get_json(silent=True) or {})
    if key is None:
        return jsonify({'error': 'Invalid key'}), 400
    return jsonify({'exists': chat_store.chat_exists(key)})


@chat_bp.route('/api/join', methods=['POST'])
def join():
    data = request.get_json(silent=True) or {}
    key = _read_key(data)
    password = data.get('password')
    if key is None:
        return jsonify({'error': 'Invalid key'}), 400
    if (not isinstance(password, str)
            or not chat_store.MIN_PASSWORD_LENGTH <= len(password) <= chat_store.MAX_PASSWORD_LENGTH):
        return jsonify({'error': f'Password must be {chat_store.MIN_PASSWORD_LENGTH}-'
                                 f'{chat_store.MAX_PASSWORD_LENGTH} characters'}), 400

    token, created = chat_store.join_chat(key, password, _client_ip())
    if token is None:
        return jsonify({'error': 'Wrong password'}), 403
    return jsonify({'token': token, 'created': created})


@chat_bp.route('/api/messages', methods=['GET'])
def list_messages():
    after_id = request.args.get('after', 0, type=int)
    result = chat_store.get_messages(_token(), after_id)
    if result is None:
        return jsonify({'error': 'Not authorized or chat expired'}), 401
    messages, oldest_id = result
    return jsonify({'messages': [_serialize(m) for m in messages], 'oldest_id': oldest_id})


@chat_bp.route('/api/messages', methods=['POST'])
def post_message():
    text = (request.get_json(silent=True) or {}).get('text')
    if not isinstance(text, str) or not text.strip():
        return jsonify({'error': 'Message is empty'}), 400
    if len(text) > chat_store.MAX_MESSAGE_LENGTH:
        return jsonify({'error': f'Message is longer than {chat_store.MAX_MESSAGE_LENGTH} characters'}), 400

    message = chat_store.add_message(_token(), _client_ip(), text)
    if message is None:
        return jsonify({'error': 'Not authorized or chat expired'}), 401
    return jsonify(_serialize(message)), 201
