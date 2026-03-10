import sqlite3
import os
import pyotp
import base64
import subprocess
import json
from functools import wraps
from datetime import datetime
from time import sleep
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, make_response, render_template, redirect, url_for, session
from flask.views import MethodView
from flask_smorest import Api, Blueprint
import marshmallow as ma

app = Flask(__name__)
app.secret_key = 'super-secret-key-for-sessions'

# --- SCHEMAS ---

class OtpArgsSchema(ma.Schema):
    seed_b32 = ma.fields.String(metadata={"description": "Base32 seed for TOTP generation"})
    seed_hex = ma.fields.String(metadata={"description": "Hex seed for TOTP generation"})

class OtpResponseSchema(ma.Schema):
    otp_code = ma.fields.String(metadata={"description": "The generated TOTP code"})
    time_remaining = ma.fields.Float(metadata={"description": "Seconds until the code expires"})
    seed_b32 = ma.fields.String(metadata={"description": "The seed used in base32 (generated if not provided)"})
    seed_hex = ma.fields.String(metadata={"description": "The seed used in hex (generated if not provided)"})

class UserSearchArgsSchema(ma.Schema):
    user_id = ma.fields.String(metadata={"description": "User ID to search for"})

### For token end-points
class AuthSchema(ma.Schema):
    username = ma.fields.String(required=True)
    password = ma.fields.String(required=True)

class GetTokenArgsSchema(ma.Schema):
    auth = ma.fields.Nested(AuthSchema, required=True)

class TokenReplySchema(ma.Schema):
    token = ma.fields.String()
    prefix = ma.fields.String()

class GetTokenResponseSchema(ma.Schema):
    reply = ma.fields.Nested(TokenReplySchema)


# OpenAPI / Swagger configuration
app.config["API_TITLE"] = "Vulnerable App API"
app.config["API_VERSION"] = "v1"
app.config["OPENAPI_VERSION"] = "3.0.2"
app.config["OPENAPI_URL_PREFIX"] = "/"
app.config["OPENAPI_JSON_PATH"] = "openapi.json"
app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"

api = Api(app)
api_blp = Blueprint("api", "api", url_prefix="/api", description="Operations on API")

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
TOKEN = "Sf54F-/f#${wf}!*aR.y%"
PREFIX = "Bearer"


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

@app.before_request
def log_requests():
    if request.path.startswith('/web/welcome-') or request.path.startswith('/api/v1/'):
        echo_data: str = _dict2str(_get_echo())

        # Log to file
        #log_entry = f"--- {datetime.now()} | {request.path} ---\n{echo_data}\n\n"
        #with open("welcome_requests.log", "a") as f:
        #    f.write(log_entry)
        
        print("\n--- REQUEST RECEIVED ---", flush=True)
        print(echo_data, flush=True)
        print("--- END REQUEST ---\n", flush=True)

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
#@requires_secret_cookie
def welcome_cookie():
    response = f'<h1>You are welcome!</h1><p>You have the required cookie {SECRET_COOKIE_NAME} = {SECRET_COOKIE_VALUE}.</p>'
    response += """This script bellow will call 
        <a href="https://vulapi.pjn.ddns.net/api/v1/header-cookie">https://vulapi.pjn.ddns.net/api/v1/header-cookie</a>
        <script type="text/javascript">
            function reqListener() {
                console.log(this.responseText);
            }
            const req = new XMLHttpRequest();
            req.addEventListener("load", reqListener);
            req.open("GET", "https://vulapi.pjn.ddns.net/api/v1/header-cookie");
            //req.withCredentials = true;
            req.send();
        </script>
    """
    return response


# 4. Re-added Original Ping Page (Command Injection)
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


### API Endpoints

# API TOOLS - Echo Endpoint
@api_blp.route('/tools/echo', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def api_echo():
    echo_data = _get_echo()
    return echo_data, 200

# API 2FA OTP Endpoint
@api_blp.route('/tools/otp')
class Otp(MethodView):
    @api_blp.arguments(OtpArgsSchema, location="query")
    @api_blp.response(200, OtpResponseSchema)
    def get(self, args):
        """Get TOTP code via query parameter"""
        seed_b32 = args.get('seed_b32', '')
        seed_hex = args.get('seed_hex', '')
        return self._process(seed_b32, seed_hex)

    @api_blp.arguments(OtpArgsSchema, location="form")
    @api_blp.response(200, OtpResponseSchema)
    def post(self, args):
        """Get TOTP code via form data"""
        seed_b32 = args.get('seed_b32', '')
        seed_hex = args.get('seed_hex', '')
        return self._process(seed_b32, seed_hex)

    def _process(self, seed_b32: str, seed_hex: str):
        try:
            result = _get_otp(seed_b32, seed_hex)
            return result
        except Exception as err:
            return {"message": str(err)}, 400

# 5. API Protected by Header + Cookie
@api_blp.route('/v1/header-cookie', methods=['GET'])
@requires_secret_header
@requires_secret_cookie
def api_secret_header_cookie():
    data = {
        "headers": dict(request.headers),
        "cookies": request.cookies,
        "info": "You've found the static headers+cookies thresure",
    }
    return data, 200, {
            'Access-Control-Allow-Origin': '*',
            #'Access-Control-Allow-Credentials': True
        }

# 6. API Protected by BasicAuth + Header + Cookie
@api_blp.route('/v1/header-cookie-auth', methods=['GET'])
@requires_basic_auth
@requires_secret_header
@requires_secret_cookie
def api_secret_header_cookie_basic_auth():
    auth = request.authorization
    data = {
        "basic-auth": {
            "username": auth.username, 
            "password": auth.password, 
        },
        "headers": dict(request.headers),
        "cookies": request.cookies,
        "info": "You've found the static headers+cookies with basic auth thresure",
    }
    return data, 200


# 7. User Search API (SQLi)
@api_blp.route('/v1/users/<user_id>')
@api_blp.arguments(UserSearchArgsSchema, location="path")
@api_blp.response(200)
def users(args, user_id):
    query = f"SELECT id, username, bio FROM users WHERE id = {user_id}"
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        try:
            results = cursor.execute(query).fetchall()
            if len(results) == 0:
                return {"error": "No result found in DB.", "query": query}, 404
        except Exception as e:
            return {"error": f"Database error: {str(e)}", "query": query}, 500
    return {"results": results, "query": query}


# Get Auth Token with JSON payload
@api_blp.route('/v1/get-token', methods=['POST'])
@api_blp.arguments(GetTokenArgsSchema, location="json")
@api_blp.response(200, GetTokenResponseSchema)
def get_token(args):
    """
    {
       "auth": {
           "username": "admin",
           "password": "easypassword"
       }
    }
    """
    auth = args.get('auth', {})
    if auth.get('username') == USERNAME and auth.get('password') == PASSWORD:
        return {
            "reply": {
                "token": TOKEN,
                "prefix": PREFIX,
            }
        }, 200
    return {"message": "Invalid Token JSON credentials"}, 400


# Get Auth Token with Form payload
@api_blp.route('/v1/get-token-form', methods=['POST'])
@api_blp.arguments(AuthSchema, location="form")
@api_blp.response(200, GetTokenResponseSchema)
def get_token_form(args):
    if args.get('username') == USERNAME and args.get('password') == PASSWORD:
        return {
            "reply": {
                "token": TOKEN,
                "prefix": PREFIX,
            }
        }, 200
    return {"message": "Invalid Token form credentials"}, 400


# Validate Auth Token
@api_blp.route('/v1/is-valid-token', methods=['GET', 'POST'])
@requires_auth_token
def good_token():
    return {"message": "You've go the correct token!"}, 200


def _get_otp(seed_b32: str = "", seed_hex: str = "") -> dict:
    """
    Generate OTP code from seed in base32 or hex format.

    Args:
        seed_b32: OTP seed as base32 string
        seed_hex: OTP seed as hex string (plain text, not bytes)

    Returns:
        dict with keys: seed_b32, seed_hex, otp_code, time_remaining
    """
    # If both are None, generate a new seed
    if len(seed_b32) + len(seed_hex) == 0:
        seed_b32 = pyotp.random_base32()

    # If only seed_hex is None, convert from seed_b32
    if seed_hex == "":
        # Add padding if needed for base32 decoding
        padding = (8 - len(seed_b32) % 8) % 8
        seed_b32_padded = seed_b32 + '=' * padding
        seed_bytes = base64.b32decode(seed_b32_padded)
        seed_hex = seed_bytes.hex()

    # If only seed_b32 is None, convert from seed_hex
    if seed_b32 == "":
        seed_bytes = bytes.fromhex(seed_hex)
        seed_b32 = base64.b32encode(seed_bytes).decode('utf-8').rstrip('=')

    # Generate OTP code using the base32 seed
    totp = pyotp.TOTP(seed_b32)
    otp_code = totp.now()
    time_remaining = (totp.interval - datetime.now().timestamp()) % totp.interval

    if time_remaining < 3.0:
        sleep(time_remaining)
        return _get_otp(seed_b32=seed_b32, seed_hex=seed_hex)
    if not totp.verify(otp_code):
        raise ValueError(f"Seed string b32='{seed_b32}' and hex='{seed_hex}' fails with otp code '{otp_code}'")

    return {
        'seed_b32': seed_b32,
        'seed_hex': seed_hex,
        'otp_code': otp_code,
        'time_remaining': time_remaining
    }


def _get_echo() -> dict:
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
    
    auth = request.authorization
    if auth:
        echo_data["basic-auth"] = {
            "username": auth.username, 
            "password": auth.password, 
        }
    return echo_data


def _dict2str(d: dict) -> str:
    return json.dumps(d, indent=2)


api.register_blueprint(api_blp)


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
