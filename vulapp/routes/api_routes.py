"""API routes for the vulnerable application."""
import sqlite3
from flask import request
from flask.views import MethodView
from flask_smorest import Blueprint
from vulapp.auth import requires_basic_auth, requires_secret_header, requires_secret_cookie, requires_auth_token
from vulapp.config import USERNAME, PASSWORD, TOKEN, PREFIX, DATABASE
from vulapp.schemas import (
    OtpArgsSchema, OtpResponseSchema, UserSearchArgsSchema,
    GetTokenArgsSchema, GetTokenResponseSchema, AuthSchema
)
from vulapp.utils import get_otp, get_echo


api_blp = Blueprint("api", "api", url_prefix="/api", description="Operations on API")


# API TOOLS - Echo Endpoint
@api_blp.route('/tools/echo', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def api_echo():
    echo_data = get_echo()
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
            result = get_otp(seed_b32, seed_hex)
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
