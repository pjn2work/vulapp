"""API routes for the vulnerable application."""
import sqlite3
from flask import request
from flask.views import MethodView
from flask_smorest import Blueprint
from graphql import get_introspection_query
from vulapp.auth import requires_basic_auth, requires_secret_header, requires_secret_cookie, requires_auth_token
from vulapp.config import (
    USERNAME, PASSWORD, TOKEN, PREFIX, DATABASE,
    OAUTH2_AUTH_CODES, OAUTH2_TOKENS
)
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


# GraphQL API Endpoint (JSON)
@api_blp.route('/v1/graphql', methods=['POST'])
@requires_secret_header
def graphql_api():
    """
    GraphQL API endpoint - returns JSON responses.
    VULNERABLE: SQL injection, no query depth limiting, introspection enabled.

    Example POST body:
    {
        "query": "{ users { id username email } }"
    }
    """
    # Import here to avoid circular dependency
    from vulapp.routes.web_routes import graphql_schema

    try:
        # Accept JSON or form data
        if request.is_json:
            data = request.get_json()
            query_string = data.get('query', '')
        else:
            query_string = request.form.get('query', '') or request.args.get('query', '')

        if not query_string:
            return {
                "errors": [{
                    "message": "No query provided. Send JSON with 'query' field or use query parameter."
                }]
            }, 400

        # Execute GraphQL query
        result = graphql_schema.execute(query_string)

        # Build response
        response = {}
        if result.data:
            response['data'] = result.data
        if result.errors:
            response['errors'] = [{"message": str(e)} for e in result.errors]

        return response, 200

    except Exception as e:
        return {
            "errors": [{
                "message": f"GraphQL execution error: {str(e)}"
            }]
        }, 500


# GraphQL Schema Export (JSON introspection)
@api_blp.route('/v1/graphql/schema', methods=['GET'])
def graphql_schema_api():
    """Export GraphQL schema via introspection query (returns JSON)."""
    from vulapp.routes.web_routes import graphql_schema

    try:
        introspection_query = get_introspection_query()
        result = graphql_schema.execute(introspection_query)

        if result.errors:
            return {
                "error": "Failed to generate schema",
                "details": str(result.errors[0])
            }, 500

        return result.data, 200

    except Exception as e:
        return {"error": str(e)}, 500


# ============================================================
# OAuth2 Token Endpoint (Intentionally Vulnerable)
# ============================================================

@api_blp.route('/v1/oauth2/token', methods=['POST'])
def oauth2_token():
    """
    OAuth2 Token Exchange Endpoint.
    Exchange an authorization code for an access token.

    VULNERABLE:
    - No client_secret validation (accepts any or none)
    - Tokens are predictable (MD5-based)
    - Auth codes can be replayed (not invalidated)

    POST body (form or JSON):
        grant_type: authorization_code
        code: <authorization_code>
        client_id: vulapp-client-001
        client_secret: super-secret-client-secret
        redirect_uri: <must match original>
    """
    import hashlib
    import time

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    grant_type = data.get('grant_type', '')
    code = data.get('code', '')
    client_id = data.get('client_id', '')
    redirect_uri = data.get('redirect_uri', '')

    if grant_type != 'authorization_code':
        return {"error": "unsupported_grant_type",
                "error_description": "Only authorization_code grant is supported"}, 400

    if not code or code not in OAUTH2_AUTH_CODES:
        return {"error": "invalid_grant",
                "error_description": "Authorization code is invalid or expired"}, 400

    code_data = OAUTH2_AUTH_CODES[code]

    if time.time() > code_data['expires']:
        del OAUTH2_AUTH_CODES[code]
        return {"error": "invalid_grant",
                "error_description": "Authorization code has expired"}, 400

    # VULNERABLE: No client_secret validation - accepts any value or none
    # A real implementation MUST validate client_secret

    # VULNERABLE: No redirect_uri matching enforcement
    # A real implementation MUST verify redirect_uri matches the one from authorization

    # VULNERABLE: Auth code NOT invalidated after use (replay attacks possible)

    # Generate access token (VULNERABLE: predictable - MD5 of code + timestamp)
    token_input = f"{code}{int(time.time())}"
    access_token = hashlib.md5(token_input.encode()).hexdigest()

    OAUTH2_TOKENS[access_token] = {
        'client_id': client_id or code_data['client_id'],
        'username': code_data['username'],
        'scope': code_data['scope'],
        'expires': time.time() + 3600,  # 1 hour
    }

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": code_data['scope'],
    }, 200


@api_blp.route('/v1/oauth2/userinfo', methods=['GET'])
def oauth2_userinfo():
    """
    OAuth2 UserInfo Endpoint - returns profile for a valid Bearer token.
    """
    import time
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return {"error": "invalid_request",
                "error_description": "Missing or malformed Authorization header. Use: Bearer <token>"}, 401

    token = auth_header[7:]
    if token not in OAUTH2_TOKENS:
        return {"error": "invalid_token",
                "error_description": "Token is invalid or expired"}, 401

    token_data = OAUTH2_TOKENS[token]
    if time.time() > token_data['expires']:
        del OAUTH2_TOKENS[token]
        return {"error": "invalid_token",
                "error_description": "Token has expired"}, 401

    return {
        "sub": token_data['username'],
        "username": token_data['username'],
        "email": f"{token_data['username']}@vulapp.local",
        "scope": token_data['scope'],
    }, 200
