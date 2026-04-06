"""Web routes for the vulnerable application."""
import os
import sqlite3
from datetime import datetime
from pathlib import Path
import subprocess
import pyotp
import json
from flask import Blueprint, request, render_template, redirect, url_for, session, make_response, jsonify, send_from_directory
from graphene import ObjectType, String, Schema, List, Field, Int
from vulapp.auth import requires_basic_auth, requires_session, requires_2fa_session, requires_secret_header, requires_secret_cookie
from vulapp.config import USERNAME, PASSWORD, TOTP_SEED, SECRET_HEADER_NAME, SECRET_HEADER_VALUE, SECRET_COOKIE_NAME, SECRET_COOKIE_VALUE, DATABASE
from vulapp.tracker import (
    get_client_ip, get_upload_count, increment_upload_count,
    track_file_deletion, track_file_download, MAX_FILES_PER_IP
)

# Get absolute path for uploads folder
UPLOAD_FOLDER = Path('uploads').resolve()

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


# 5. User Search (SQL Injection)
@web_bp.route('/web/users')
def users():
    search = request.args.get('search', '')
    results = []
    query = ""

    if search:
        # VULNERABLE: SQL Injection
        query = f"SELECT username, bio FROM users WHERE username LIKE '%{search}%'"
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            try:
                results = cursor.execute(query).fetchall()
            except Exception as e:
                # Still render the page with the error visible in query
                pass

    return render_template('users.html', results=results, query=query)


# GraphQL Schema (Intentionally Vulnerable)
class UserType(ObjectType):
    """GraphQL User type."""
    id = Int()
    username = String()
    email = String()
    bio = String()
    password = String()  # VULNERABLE: Exposing password field


class Query(ObjectType):
    """GraphQL Query type."""
    users = List(UserType, search=String())
    user = Field(UserType, id=Int(), username=String())

    def resolve_users(self, info, search=None):
        """Resolve users query - fetches from database."""
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            if search:
                # VULNERABLE: Direct string interpolation in SQL (via GraphQL)
                query = f"SELECT rowid, username, username || '@vulapp.local', bio, 'hidden' FROM users WHERE username LIKE '%{search}%'"
            else:
                query = "SELECT rowid, username, username || '@vulapp.local', bio, 'hidden' FROM users"

            try:
                results = cursor.execute(query).fetchall()
                return [
                    UserType(id=r[0], username=r[1], email=r[2], bio=r[3], password=r[4])
                    for r in results
                ]
            except Exception:
                return []

    def resolve_user(self, info, id=None, username=None):
        """Resolve single user query."""
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            if id:
                query = f"SELECT rowid, username, username || '@vulapp.local', bio, 'hidden' FROM users WHERE rowid = {id}"
            elif username:
                # VULNERABLE: Direct string interpolation
                query = f"SELECT rowid, username, username || '@vulapp.local', bio, 'hidden' FROM users WHERE username = '{username}'"
            else:
                return None

            try:
                result = cursor.execute(query).fetchone()
                if result:
                    return UserType(id=result[0], username=result[1], email=result[2], bio=result[3], password=result[4])
            except Exception:
                pass
        return None


# Create GraphQL schema
graphql_schema = Schema(query=Query)


# 5b. GraphQL Query Interface (Multiple Vulnerabilities)
@web_bp.route('/web/graphql', methods=['GET', 'POST'])
def graphql_interface():
    """GraphQL query interface - VULNERABLE to injection, introspection, no depth limiting."""
    query_string = ""
    result = None
    error = None

    if request.method == 'POST':
        query_string = request.form.get('query', '')
    else:
        query_string = request.args.get('query', '')

    if query_string:
        try:
            # VULNERABLE: No query validation, depth limiting, or complexity analysis
            # Allows introspection queries, deeply nested queries, batch attacks
            result = graphql_schema.execute(query_string)

            if result.errors:
                error = str(result.errors[0])

        except Exception as e:
            error = str(e)

    return render_template('graphql.html',
                         query=query_string,
                         result=result.data if result and not error else None,
                         error=error)


# 6. Guestbook (Reflected XSS)
@web_bp.route('/web/guestbook')
def guestbook():
    name = request.args.get('name', '')
    return render_template('guestbook.html', name=name)


@web_bp.route('/web/logout')
def logout():
    session.clear()
    return redirect(url_for('web.index'))


# File Upload and Download Routes
@web_bp.route('/web/upload-file', methods=['POST'])
def upload_file():
    """Handle file upload with size limit and name collision handling."""
    # Get client IP
    client_ip = get_client_ip()

    # Check upload limit for this IP
    current_count = get_upload_count(client_ip)
    if current_count >= MAX_FILES_PER_IP:
        return jsonify({
            'error': f'Upload limit reached. You have uploaded {current_count}/{MAX_FILES_PER_IP} files. Maximum {MAX_FILES_PER_IP} files per user.'
        }), 429  # Too Many Requests

    # Create uploads directory if it doesn't exist
    UPLOAD_FOLDER.mkdir(exist_ok=True)

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Check file size (100MB limit)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    max_size = 100 * 1024 * 1024  # 100MB in bytes
    if file_size > max_size:
        return jsonify({'error': f'File size ({file_size / (1024*1024):.2f}MB) exceeds 100MB limit'}), 413

    # Handle file name collision
    file_path = UPLOAD_FOLDER / file.filename

    if file_path.exists():
        # Get file modification time
        mod_time = datetime.fromtimestamp(file_path.stat().st_mtime)
        timestamp = mod_time.strftime('%Y%m%d_%H%M%S')

        # Split filename and extension
        stem = file_path.stem
        suffix = file_path.suffix

        # Rename old file with timestamp
        old_file_path = UPLOAD_FOLDER / f"{stem}_{timestamp}{suffix}"
        file_path.rename(old_file_path)

    # Save the new file
    file.save(file_path)

    # Increment upload count for this IP and track the file with size
    increment_upload_count(client_ip, file.filename, file_size)

    # Get updated count
    new_count = get_upload_count(client_ip)
    remaining = MAX_FILES_PER_IP - new_count

    return jsonify({
        'success': True,
        'message': f'File "{file.filename}" uploaded successfully ({new_count}/{MAX_FILES_PER_IP} files used, {remaining} remaining)',
        'size': file_size,
        'uploads_used': new_count,
        'uploads_remaining': remaining
    }), 200


@web_bp.route('/web/files')
def files_browser():
    """Render the file browser page."""
    return render_template('files.html')


@web_bp.route('/web/list-files')
def list_files():
    """List all uploaded files with metadata."""
    UPLOAD_FOLDER.mkdir(exist_ok=True)

    files = []
    for file_path in UPLOAD_FOLDER.iterdir():
        if file_path.is_file():
            stat = file_path.stat()
            files.append({
                'name': file_path.name,
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })

    files.sort(key=lambda x: x['modified'], reverse=True)
    return jsonify(files)


@web_bp.route('/web/upload-quota')
def upload_quota():
    """Get upload quota information for the current IP."""
    client_ip = get_client_ip()
    current_count = get_upload_count(client_ip)
    remaining = MAX_FILES_PER_IP - current_count

    return jsonify({
        'uploads_used': current_count,
        'uploads_limit': MAX_FILES_PER_IP,
        'uploads_remaining': remaining,
        'percentage': round((current_count / MAX_FILES_PER_IP) * 100, 1)
    })


@web_bp.route('/web/download/<filename>')
def download_file(filename):
    """Download a file from the uploads folder."""
    # Ensure the uploads folder exists
    UPLOAD_FOLDER.mkdir(exist_ok=True)

    # Get file size for tracking
    file_path = UPLOAD_FOLDER / filename
    file_size = file_path.stat().st_size if file_path.exists() else 0

    # Track the download with size
    client_ip = get_client_ip()
    track_file_download(client_ip, filename, file_size)

    # send_from_directory needs a string path
    return send_from_directory(str(UPLOAD_FOLDER), filename, as_attachment=True)


@web_bp.route('/web/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    """Delete a file from the uploads folder."""
    try:
        file_path = UPLOAD_FOLDER / filename

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        # Get file size before deleting
        file_size = file_path.stat().st_size

        # Delete the file
        file_path.unlink()

        # Track the deletion with size
        client_ip = get_client_ip()
        track_file_deletion(client_ip, filename, file_size)

        return jsonify({
            'success': True,
            'message': f'File "{filename}" deleted successfully'
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to delete file: {str(e)}'}), 500
