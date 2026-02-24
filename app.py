
import sqlite3
import os
import pyotp
import subprocess
import json
from functools import wraps
from datetime import datetime
from time import sleep
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, make_response, render_template, redirect, url_for, session


app = Flask(__name__)
app.secret_key = 'super-secret-key-for-sessions'

# Handle proxy headers (like X-Forwarded-Proto from Nginx)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

### Constants ###
# for requires_header
SECRET_HEADER_NAME = "secret-header"
SECRET_HEADER_VALUE = "my-secret-header"
# for requires_secret_cookie
SECRET_COOKIE_NAME = "secret-cookie"
SECRET_COOKIE_VALUE = "my-secret-cookie"
# for login_2fa
TOTP_SEED = "XVQ2UIGO75XRUKJO"
# for SQL injection
DATABASE = 'pentest_target.db'
# for all logins
USERNAME = 'admin'
PASSWORD = 'easypassword'


def init_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE) # Reset for clean demo
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, bio TEXT)")
        cursor.execute(f"INSERT INTO users (username, password, bio) VALUES ('{USERNAME}', '{PASSWORD}', 'Administrator account')")
        cursor.execute("INSERT INTO users (username, password, bio) VALUES ('guest', 'guest123', 'Regular guest user')")
        conn.commit()

init_db()

# --- AUTH DECORATORS ---

def requires_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == USERNAME and auth.password == PASSWORD):
            return make_response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated

def requires_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return f"You must login first! Using the /web/login address", 401
        return f(*args, **kwargs)
    return decorated

def requires_2fa_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('2fa_logged_in'):
            return "You must login first! Using the /web/login-2fa address", 401
        return f(*args, **kwargs)
    return decorated

def requires_secret_header(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header_value = request.headers.get(SECRET_HEADER_NAME, '')
        if header_value != SECRET_HEADER_VALUE:
            return f"You must set header {SECRET_HEADER_NAME}: {SECRET_HEADER_VALUE} - (received '{header_value}')", 500
        return f(*args, **kwargs)
    return decorated

def requires_secret_cookie(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cookie_value = request.cookies.get(SECRET_COOKIE_NAME, '')
        if cookie_value != SECRET_COOKIE_VALUE:
            return f"You must set cookie {SECRET_COOKIE_NAME}={SECRET_COOKIE_VALUE} - (received '{cookie_value}')", 500
        return f(*args, **kwargs)
    return decorated

@app.before_request
def log_welcome_requests():
    if request.path.startswith('/web/welcome-'):
        echo_data: str = __dict2str(__get_echo())

        #log_entry = f"--- {datetime.now()} | {request.path} ---\n{echo_data}\n\n"
        #with open("welcome_requests.log", "a") as f:
        #    f.write(log_entry)
        
        print("\n--- WEB REQUEST RECEIVED ---", flush=True)
        print(echo_data, flush=True)
        print("--- END WEB ---\n", flush=True)

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')


# 2. Simple Login (User + Pass) -> VULNERABLE TO SQLi BYPASS
@app.route('/web/login', methods=['GET', 'POST'])
def login_simple():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Verify Credentials
        if username == USERNAME and password == PASSWORD:
            try:
                session['username'] = username
                session['logged_in'] = True
                response = make_response(redirect(url_for('welcome_simple')))
                #response.set_cookie(SECRET_COOKIE_NAME, SECRET_COOKIE_VALUE)
                return response
            except Exception as ex:
                return render_template('login_simple.html', error_message=f"Error: {str(ex)}"), 500
        
        return render_template('login_simple.html', error_message="Invalid credentials."), 401
    return render_template('login_simple.html')


# 3. 2FA Login (User + Pass + TOTP)
@app.route('/web/login-2fa', methods=['GET', 'POST'])
def login_2fa():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp', '')
        
        # Verify Credentials
        if username == USERNAME and password == PASSWORD:
            try:
                totp = pyotp.TOTP(TOTP_SEED)
                if totp.verify(otp):
                    session['username'] = username
                    session['2fa_logged_in'] = True
                    response = make_response(redirect(url_for('welcome_2fa')))
                    #response.set_cookie(SECRET_COOKIE_NAME, SECRET_COOKIE_VALUE)
                    return response
                return render_template('login_2fa.html', error_message=f"Invalid 2FA code '{otp}' for seed {TOTP_SEED}"), 401
            except Exception as ex:
                return render_template('login_2fa.html', error_message=f"Error: {ex}"), 404
        return render_template('login_2fa.html', error_message="Invalid credentials or OTP code."), 401
        
    return render_template('login_2fa.html')


### Test URLs

# 1. Basic Auth Page
@app.route('/web/welcome-basic-auth')
@requires_basic_auth
def basic_auth_login():
    auth = request.authorization
    username = auth.username
    return f"<h1>You are welcome {username}!</h1><p>You have successfully logged in using basic-auth.</p>"

@app.route('/web/welcome-simple')
@requires_session
def welcome_simple():
    # VULNERABLE: Reflected XSS via username
    username = session.get('username', '!NOT FOUND!')
    return render_template('welcome_simple.html', username=username)

@app.route('/web/welcome-2fa')
@requires_2fa_session
def welcome_2fa():
    # VULNERABLE: Reflected XSS via username
    username = session.get('username', '!NOT FOUND!')
    return f"<h1>You are welcome {username}!</h1><p>You have successfully logged in with 2FA.</p>"

@app.route('/web/welcome-header')
@requires_secret_header
def welcome_header():
    return f"<h1>You are welcome!</h1><p>You have the required header {SECRET_HEADER_NAME}: {SECRET_HEADER_VALUE}.</p>"

@app.route('/web/welcome-cookie')
@requires_secret_cookie
def welcome_cookie():
    return f"<h1>You are welcome!</h1><p>You have the required cookie {SECRET_COOKIE_NAME} = {SECRET_COOKIE_VALUE}.</p>"


# 4. Re-added Original Users Page (SQLi)
@app.route('/web/users')
def users():
    search = request.args.get('search', '')
    query = f"SELECT username, bio FROM users WHERE username LIKE '%{search}%'"
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        try:
            results = cursor.execute(query).fetchall()
        except Exception as e:
            return f"Database error: {str(e)}", 500
    return render_template('users.html', results=results, query=query)


# 5. Re-added Original Ping Page (Command Injection)
@app.route('/web/ping')
def ping():
    host = request.args.get('host', '')
    output = ""
    if host:
        try:
            output = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            output = e.output
    return render_template('ping.html', output=output, host=host)

@app.route('/web/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# 6. API Echo Endpoint
@app.route('/api/echo', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def api_echo():
    echo_data = __get_echo()
    return echo_data, 200


@app.route('/api/otp', methods=['GET', 'POST'])
def get_otp():
    seed: str = request.form.get('seed', '') if request.method == 'POST' else request.args.get('seed', '')
    try:
        code, time_remaining, seed_b32_str = __get_otp(seed)
        echo_data = {
            "code": code,
            "time_remaining": time_remaining,
            "seed_b32_str": seed_b32_str,
        }
    except Exception as err:
        return str(err), 404
    return echo_data, 200


def __get_otp(seed_b32_str: str = "") -> tuple[str, float, str]:
    if not seed_b32_str:
        seed_b32_str = pyotp.random_base32()
    totp = pyotp.TOTP(seed_b32_str)
    code = totp.now()
    time_remaining = (totp.interval - datetime.now().timestamp()) % totp.interval
    if time_remaining < 3.0:
        sleep(time_remaining)
        return __get_otp(seed_b32_str=seed_b32_str)
    if not totp.verify(code):
        raise ValueError(f"Seed string in b32 '{seed_b32_str} fails with code '{code}'")
    return code, time_remaining, seed_b32_str


def __get_echo() -> dict:
    echo_data = {
        "scheme": request.scheme,
        "is_https": request.is_secure,
        "full_url": request.url,
        "path": request.path,
        "method": request.method,
        "headers": dict(request.headers),
        "query_params": dict(request.args),
        "payload": request.get_data(as_text=True),
        "session": {k: v for k, v in session.items()},
        "cookies": {k: v for k, v in request.cookies.items()}
    }
    
    # Print to logs/console
    print("\n--- API ECHO REQUEST RECEIVED ---", flush=True)
    print(__dict2str(echo_data), flush=True)
    print("--- END API ECHO ---\n", flush=True)

    return echo_data


def __dict2str(d: dict) -> str:
    return json.dumps(d, indent=2)


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
