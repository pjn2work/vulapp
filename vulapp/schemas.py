"""Marshmallow schemas for API validation."""
import marshmallow as ma


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
