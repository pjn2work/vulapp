"""Storage for the hidden chat feature.

Chats live in a JSON file. Every read-modify-write runs under an exclusive file lock,
so several requests (or uWSGI workers) can't overwrite each other's changes.

Nothing sensitive is stored in plaintext:
- chats are indexed by SHA-256 of the chat key
- passwords are stored as Werkzeug salted hashes
- access tokens are stored as SHA-256 hashes
"""
import fcntl
import hashlib
import json
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

CHAT_STORE_FILE = Path('chat_store.json')
CHAT_LOCK_FILE = Path('chat_store.lock')

HISTORY_SECONDS = 24 * 60 * 60   # messages expire after 24h; a chat is deleted once it has no messages left
TOKEN_SECONDS = 15 * 60          # an access token is valid for 15 min; then you must re-enter the password
MAX_MESSAGES_PER_CHAT = 1000     # oldest messages are dropped beyond this
MAX_MESSAGE_LENGTH = 2000
MAX_KEY_LENGTH = 256
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 128
CHAT_CREATED_MESSAGE = 'Chat created'  # first message, so a new chat lives for at least 24h
POLL_INTERVAL_SECONDS = 5       # how often the chat page fetches new messages


def _sha256(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _empty_store():
    return {'chats': {}, 'tokens': {}}


@contextmanager
def _locked_store():
    """Yield the store under an exclusive lock and save it afterwards if it changed."""
    with open(CHAT_LOCK_FILE, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            store = _empty_store()
            if CHAT_STORE_FILE.exists():
                try:
                    with open(CHAT_STORE_FILE, 'r') as f:
                        store = json.load(f)
                except (json.JSONDecodeError, IOError):
                    store = _empty_store()
            before = json.dumps(store, sort_keys=True)
            _prune(store)
            yield store
            if json.dumps(store, sort_keys=True) != before:
                _save(store)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _save(store):
    """Write atomically: a crash mid-write never leaves a truncated file behind."""
    tmp_path = CHAT_STORE_FILE.with_suffix('.tmp')
    with open(tmp_path, 'w') as f:
        json.dump(store, f)
    os.replace(tmp_path, CHAT_STORE_FILE)


def _prune(store):
    """Drop expired messages, chats with no messages left, and expired or orphaned tokens.

    Deleting a chat frees its key: the next person to enter it creates a new chat and sets a new password.
    """
    now = time.time()
    message_cutoff = now - HISTORY_SECONDS
    for chat_id in list(store['chats']):
        chat = store['chats'][chat_id]
        chat['messages'] = [m for m in chat['messages'] if m['ts'] >= message_cutoff]
        if not chat['messages']:
            del store['chats'][chat_id]
    max_expires = now + TOKEN_SECONDS  # also drops tokens issued under a longer TOKEN_SECONDS
    for token_hash in list(store['tokens']):
        token = store['tokens'][token_hash]
        if not now <= token['expires'] <= max_expires or token['chat'] not in store['chats']:
            del store['tokens'][token_hash]


def _issue_token(store, chat_id):
    token = secrets.token_urlsafe(32)
    store['tokens'][_sha256(token)] = {'chat': chat_id, 'expires': time.time() + TOKEN_SECONDS}
    return token


def chat_exists(key):
    with _locked_store() as store:
        return _sha256(key) in store['chats']


def join_chat(key, password, ip):
    """Create the chat if the key is new (the password becomes its password, and a first message is added
    so the chat isn't empty), otherwise verify the password. Returns (token, created) or (None, False) on a bad password."""
    chat_id = _sha256(key)
    with _locked_store() as store:
        chat = store['chats'].get(chat_id)
        if chat is None:
            now = time.time()
            store['chats'][chat_id] = {
                'password_hash': generate_password_hash(password),
                'created': now,
                'next_id': 2,
                'messages': [{'id': 1, 'ts': now, 'ip': ip, 'text': CHAT_CREATED_MESSAGE}],
            }
            return _issue_token(store, chat_id), True
        if not check_password_hash(chat['password_hash'], password):
            return None, False
        return _issue_token(store, chat_id), False


def _chat_for_token(store, token):
    if not token:
        return None
    entry = store['tokens'].get(_sha256(token))
    if entry is None:
        return None
    return store['chats'].get(entry['chat'])


def revoke_token(token):
    """Delete the token so it stops working immediately. Unknown tokens are ignored."""
    if not token:
        return
    with _locked_store() as store:
        store['tokens'].pop(_sha256(token), None)


def get_messages(token, after_id=0):
    """Return (messages newer than after_id, oldest id still kept), or None if the token is invalid."""
    with _locked_store() as store:
        chat = _chat_for_token(store, token)
        if chat is None:
            return None
        messages = [m for m in chat['messages'] if m['id'] > after_id]
        oldest_id = chat['messages'][0]['id'] if chat['messages'] else chat['next_id']
        return messages, oldest_id


def add_message(token, ip, text):
    """Append a message. Returns the stored message, or None if the token is invalid."""
    with _locked_store() as store:
        chat = _chat_for_token(store, token)
        if chat is None:
            return None
        now = time.time()
        message = {'id': chat['next_id'], 'ts': now, 'ip': ip, 'text': text}
        chat['next_id'] += 1
        chat['messages'].append(message)
        if len(chat['messages']) > MAX_MESSAGES_PER_CHAT:
            chat['messages'] = chat['messages'][-MAX_MESSAGES_PER_CHAT:]
        return message
