"""Storage for the hidden chat feature.

Chats live in a JSON file. Every read-modify-write runs under an exclusive file lock,
so several requests (or uWSGI workers) can't overwrite each other's changes.

Nothing sensitive is stored in plaintext:
- chats are indexed by SHA-256 of the chat key
- message text and sender IP are encrypted with AES-256-GCM, using a key derived (scrypt) from the chat key
  and password; the file only holds a verifier for the password, never the encryption key itself
- access tokens are stored as SHA-256 hashes; each token entry holds the chat's encryption key, encrypted with
  a key derived from the token, so only whoever holds the token can open it
The server still sees plaintext while it handles a request: this protects the file at rest, it isn't end-to-end.

Expired data is removed on every access. Run `python -m vulapp.chat_store prune` periodically (cron) to also
remove it from disk while nobody uses the chat.
"""
import base64
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1  # same cost as Werkzeug's default password hashes


def _sha256(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _derive(key, password, salt):
    """Return (encryption key, password verifier) for a chat, both from a single scrypt run."""
    secret = json.dumps([key, password]).encode('utf-8')  # unambiguous, unlike plain concatenation
    derived = hashlib.scrypt(secret, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                             maxmem=64 * 1024 * 1024, dklen=64)
    return derived[:32], derived[32:].hex()


def _encrypt(key, plaintext, aad):
    nonce = secrets.token_bytes(12)
    return _b64(nonce + AESGCM(key).encrypt(nonce, plaintext, aad))


def _decrypt(key, blob, aad):
    data = base64.b64decode(blob)
    return AESGCM(key).decrypt(data[:12], data[12:], aad)


def _token_wrap_key(token):
    return hashlib.sha256(b'chat-token-wrap:' + token.encode('utf-8')).digest()


def _message_aad(chat_id, message_id):
    # Binds each ciphertext to its chat and id, so messages can't be moved between chats or reordered in the file
    return f'{chat_id}:{message_id}'.encode('ascii')


def _empty_store():
    return {'chats': {}, 'tokens': {}}


@contextmanager
def _open_store():
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
            yield store
            if json.dumps(store, sort_keys=True) != before:
                _save(store)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


@contextmanager
def _locked_store():
    """Like _open_store, with expired data already removed."""
    with _open_store() as store:
        _prune(store)
        yield store


def _save(store):
    """Write atomically: a crash mid-write never leaves a truncated file behind."""
    tmp_path = CHAT_STORE_FILE.with_suffix('.tmp')
    with open(tmp_path, 'w') as f:
        json.dump(store, f)
    os.replace(tmp_path, CHAT_STORE_FILE)


def _prune(store):
    """Drop expired messages, chats with no messages left, and expired or orphaned tokens.
    Returns how many messages, chats and tokens were removed.

    Deleting a chat frees its key: the next person to enter it creates a new chat and sets a new password.
    """
    now = time.time()
    removed = {'messages': 0, 'chats': 0, 'tokens': 0}
    message_cutoff = now - HISTORY_SECONDS
    for chat_id in list(store['chats']):
        chat = store['chats'][chat_id]
        # Chats created before encryption was added have no salt and can't be opened anymore: drop them
        kept = [m for m in chat['messages'] if m['ts'] >= message_cutoff] if 'salt' in chat else []
        removed['messages'] += len(chat['messages']) - len(kept)
        chat['messages'] = kept
        if not kept:
            del store['chats'][chat_id]
            removed['chats'] += 1
    max_expires = now + TOKEN_SECONDS  # also drops tokens issued under a longer TOKEN_SECONDS
    for token_hash in list(store['tokens']):
        token = store['tokens'][token_hash]
        if not now <= token['expires'] <= max_expires or token['chat'] not in store['chats']:
            del store['tokens'][token_hash]
            removed['tokens'] += 1
    return removed


def prune():
    """Remove expired data from disk. Returns how many messages, chats and tokens were removed."""
    with _open_store() as store:
        return _prune(store)


def _issue_token(store, chat_id, chat_key):
    token = secrets.token_urlsafe(32)
    store['tokens'][_sha256(token)] = {
        'chat': chat_id,
        'expires': time.time() + TOKEN_SECONDS,
        'wrapped_key': _encrypt(_token_wrap_key(token), chat_key, chat_id.encode('ascii')),
    }
    return token


def _append_message(chat_id, chat, chat_key, ip, text):
    """Encrypt and append a message. Returns it in plaintext."""
    message = {'id': chat['next_id'], 'ts': time.time(), 'ip': ip, 'text': text}
    payload = json.dumps({'ip': ip, 'text': text}).encode('utf-8')
    chat['messages'].append({
        'id': message['id'],
        'ts': message['ts'],
        'data': _encrypt(chat_key, payload, _message_aad(chat_id, message['id'])),
    })
    chat['next_id'] += 1
    if len(chat['messages']) > MAX_MESSAGES_PER_CHAT:
        chat['messages'] = chat['messages'][-MAX_MESSAGES_PER_CHAT:]
    return message


def _read_message(chat_id, chat_key, stored):
    payload = json.loads(_decrypt(chat_key, stored['data'], _message_aad(chat_id, stored['id'])))
    return {'id': stored['id'], 'ts': stored['ts'], 'ip': payload['ip'], 'text': payload['text']}


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
            salt = secrets.token_bytes(16)
            chat_key, verifier = _derive(key, password, salt)
            chat = store['chats'][chat_id] = {
                'salt': _b64(salt),
                'verifier': verifier,
                'created': time.time(),
                'next_id': 1,
                'messages': [],
            }
            _append_message(chat_id, chat, chat_key, ip, CHAT_CREATED_MESSAGE)
            return _issue_token(store, chat_id, chat_key), True
        chat_key, verifier = _derive(key, password, base64.b64decode(chat['salt']))
        if not hmac.compare_digest(verifier, chat['verifier']):
            return None, False
        return _issue_token(store, chat_id, chat_key), False


def _open_chat(store, token):
    """Return (chat_id, chat, chat encryption key) for a valid token, or None."""
    if not token:
        return None
    entry = store['tokens'].get(_sha256(token))
    if entry is None:
        return None
    chat_id = entry['chat']
    try:
        chat_key = _decrypt(_token_wrap_key(token), entry['wrapped_key'], chat_id.encode('ascii'))
    except (InvalidTag, KeyError, ValueError):
        return None
    return chat_id, store['chats'][chat_id], chat_key  # _prune already removed tokens of deleted chats


def revoke_token(token):
    """Delete the token so it stops working immediately. Unknown tokens are ignored."""
    if not token:
        return
    with _locked_store() as store:
        store['tokens'].pop(_sha256(token), None)


def get_messages(token, after_id=0):
    """Return (messages newer than after_id, oldest id still kept), or None if the token is invalid."""
    with _locked_store() as store:
        opened = _open_chat(store, token)
        if opened is None:
            return None
        chat_id, chat, chat_key = opened
        messages = [_read_message(chat_id, chat_key, m) for m in chat['messages'] if m['id'] > after_id]
        oldest_id = chat['messages'][0]['id'] if chat['messages'] else chat['next_id']
        return messages, oldest_id


def add_message(token, ip, text):
    """Append a message. Returns the stored message, or None if the token is invalid."""
    with _locked_store() as store:
        opened = _open_chat(store, token)
        if opened is None:
            return None
        chat_id, chat, chat_key = opened
        return _append_message(chat_id, chat, chat_key, ip, text)


if __name__ == '__main__':
    # Run from the directory the app runs in (the store paths are relative), e.g. from cron:
    #   cd /path/to/vulapp && python -m vulapp.chat_store prune
    if sys.argv[1:] != ['prune']:
        sys.exit('usage: python -m vulapp.chat_store prune')
    removed = prune()
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} chat prune: removed {removed['messages']} messages, "
          f"{removed['chats']} chats, {removed['tokens']} tokens", flush=True)
