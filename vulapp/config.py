"""Configuration and constants for the vulnerable app."""

# Authentication constants
SECRET_HEADER_NAME = "secret-header"
SECRET_HEADER_VALUE = "my-secret-header"
SECRET_COOKIE_NAME = "secret-cookie"
SECRET_COOKIE_VALUE = "my-secret-cookie"
TOTP_SEED = "XVQ2UIGO75XRUKJO"

# Database
DATABASE = 'pentest_target.db'

# Login credentials
USERNAME = 'admin'
PASSWORD = 'easypassword'
TOKEN = "Sf54F-/f#${wf}!*aR.y%"
PREFIX = "Bearer"

# OAuth2 configuration
OAUTH2_CLIENT_ID = "vulapp-client-001"
OAUTH2_CLIENT_SECRET = "super-secret-client-secret"
OAUTH2_AUTH_CODES = {}  # In-memory store: {code: {client_id, redirect_uri, username, expires}}
OAUTH2_TOKENS = {}  # In-memory store: {token: {client_id, username, scope, expires}}

# MLE (Message Level Encryption) - RSA-OAEP + A256GCM
MLE_KID = "mle-key-001"

def _ensure_mle_keys():
    import os
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    private_path = f"uploads/{MLE_KID}_private.pem"
    public_path = f"uploads/{MLE_KID}_public.pem"
    if not os.path.exists(private_path) or not os.path.exists(public_path):
        os.makedirs("uploads", exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(private_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(public_path, "wb") as f:
            f.write(key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

_ensure_mle_keys()
MLE_PUBLIC_KEY = open(f"uploads/{MLE_KID}_public.pem").read()
MLE_PRIVATE_KEY = open(f"uploads/{MLE_KID}_private.pem").read()

# Flask configuration
FLASK_CONFIG = {
    "SECRET_KEY": 'super-secret-key-for-sessions',
    "API_TITLE": "Vulnerable App API",
    "API_VERSION": "v1",
    "OPENAPI_VERSION": "3.0.2",
    "OPENAPI_URL_PREFIX": "/",
    "OPENAPI_JSON_PATH": "openapi.json",
    "OPENAPI_SWAGGER_UI_PATH": "/swagger-ui",
    "OPENAPI_SWAGGER_UI_URL": "https://cdn.jsdelivr.net/npm/swagger-ui-dist/",
}
