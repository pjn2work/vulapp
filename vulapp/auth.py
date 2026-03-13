"""Authentication decorators for route protection."""
from functools import wraps
from flask import request, make_response, session
from vulapp.config import (
    USERNAME, PASSWORD, TOKEN, PREFIX,
    SECRET_HEADER_NAME, SECRET_HEADER_VALUE,
    SECRET_COOKIE_NAME, SECRET_COOKIE_VALUE
)


def requires_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == USERNAME and auth.password == PASSWORD):
            return make_response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials', 406,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated


def requires_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return f"You must login first! Using the /web/login address", 402
        return f(*args, **kwargs)
    return decorated


def requires_2fa_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('2fa_logged_in'):
            return "You must login first! Using the /web/login-2fa address", 403
        return f(*args, **kwargs)
    return decorated


def requires_secret_header(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header_value = request.headers.get(SECRET_HEADER_NAME, '')
        if header_value != SECRET_HEADER_VALUE:
            return (
                f"You must set header {SECRET_HEADER_NAME}: {SECRET_HEADER_VALUE} - (received '{header_value}')",
                501,
                {
                    'Access-Control-Allow-Origin': '*',
                    #'Access-Control-Allow-Credentials': True
                }
            )
        return f(*args, **kwargs)
    return decorated


def requires_secret_cookie(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cookie_value = request.cookies.get(SECRET_COOKIE_NAME, '')
        if cookie_value != SECRET_COOKIE_VALUE:
            return (
                f"You must set cookie {SECRET_COOKIE_NAME}={SECRET_COOKIE_VALUE} - (received '{cookie_value}')",
                502,
                {
                    'Access-Control-Allow-Origin': '*',
                    #'Access-Control-Allow-Credentials': True
                }
            )
        return f(*args, **kwargs)
    return decorated


def requires_auth_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header_value = request.headers.get('token', '')
        if header_value != PREFIX + " " + TOKEN:
            return (
                f"You must get your token from /api/v1/get-token \n--received '{header_value}'\ninstead of '{PREFIX} {TOKEN}'",
                501
            )
        return f(*args, **kwargs)
    return decorated
