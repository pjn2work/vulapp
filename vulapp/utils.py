"""Utility functions for the application."""
import pyotp
import base64
import json
from datetime import datetime
from time import sleep
from flask import request, session


def get_otp(seed_b32: str = "", seed_hex: str = "") -> dict:
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
        return get_otp(seed_b32=seed_b32, seed_hex=seed_hex)
    if not totp.verify(otp_code):
        raise ValueError(f"Seed string b32='{seed_b32}' and hex='{seed_hex}' fails with otp code '{otp_code}'")

    return {
        'seed_b32': seed_b32,
        'seed_hex': seed_hex,
        'otp_code': otp_code,
        'time_remaining': time_remaining
    }


def get_echo() -> dict:
    """Get request echo data for logging/debugging."""
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


def dict2str(d: dict) -> str:
    """Convert dictionary to formatted JSON string."""
    return json.dumps(d, indent=2)
