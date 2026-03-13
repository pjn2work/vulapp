"""Web routes for the vulnerable application."""
import subprocess
import pyotp
from flask import Blueprint, request, render_template, redirect, url_for, session, make_response
from vulapp.auth import requires_basic_auth, requires_session, requires_2fa_session, requires_secret_header, requires_secret_cookie
from vulapp.config import USERNAME, PASSWORD, TOTP_SEED, SECRET_HEADER_NAME, SECRET_HEADER_VALUE, SECRET_COOKIE_NAME, SECRET_COOKIE_VALUE

web_bp = Blueprint('web', __name__)


@web_bp.route('/')
def index():
    return render_template('index.html')


# 1. Basic Auth Page
@web_bp.route('/web/welcome-basic-auth')
@requires_basic_auth
def basic_auth_login():
    auth = request.authorization
    username = auth.username
    return f"<h1>You are welcome {username}!</h1><p>You have successfully logged in using basic-auth.</p>"


# 2. Simple Login (User + Pass) -> VULNERABLE TO SQLi BYPASS
@web_bp.route('/web/login', methods=['GET', 'POST'])
def login_simple():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Verify Credentials
        if username == USERNAME and password == PASSWORD:
            try:
                session['username'] = username
                session['logged_in'] = True
                response = make_response(redirect(url_for('web.welcome_simple')))
                #response.set_cookie(SECRET_COOKIE_NAME, SECRET_COOKIE_VALUE)
                return response
            except Exception as ex:
                return render_template('login_simple.html', error_message=f"Error: {str(ex)}"), 500

        return render_template('login_simple.html', error_message="Invalid credentials."), 401
    return render_template('login_simple.html')


@web_bp.route('/web/welcome-simple')
@requires_session
def welcome_simple():
    # VULNERABLE: Reflected XSS via username
    username = session.get('username', '!NOT FOUND!')
    return render_template('welcome_simple.html', username=username)


# 3. 2FA Login (User + Pass + TOTP)
@web_bp.route('/web/login-2fa', methods=['GET', 'POST'])
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
                    response = make_response(redirect(url_for('web.welcome_2fa')))
                    #response.set_cookie(SECRET_COOKIE_NAME, SECRET_COOKIE_VALUE)
                    return response
                return render_template('login_2fa.html', error_message=f"Invalid 2FA code '{otp}' for seed {TOTP_SEED}"), 401
            except Exception as ex:
                return render_template('login_2fa.html', error_message=f"Error: {ex}"), 404
        return render_template('login_2fa.html', error_message="Invalid credentials or OTP code."), 401

    return render_template('login_2fa.html')


@web_bp.route('/web/welcome-2fa')
@requires_2fa_session
def welcome_2fa():
    # VULNERABLE: Reflected XSS via username
    username = session.get('username', '!NOT FOUND!')
    return f"<h1>You are welcome {username}!</h1><p>You have successfully logged in with 2FA.</p>"


@web_bp.route('/web/welcome-header')
@requires_secret_header
def welcome_header():
    return f"<h1>You are welcome!</h1><p>You have the required header {SECRET_HEADER_NAME}: {SECRET_HEADER_VALUE}.</p>"


@web_bp.route('/web/welcome-cookie')
@requires_secret_cookie
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
@web_bp.route('/web/ping')
def ping():
    host = request.args.get('host', '')
    output = ""
    if host:
        try:
            output = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            output = e.output
    return render_template('ping.html', output=output, host=host)


@web_bp.route('/web/logout')
def logout():
    session.clear()
    return redirect(url_for('web.index'))
