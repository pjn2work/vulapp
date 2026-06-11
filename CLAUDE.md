 CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulApp is an intentionally vulnerable Flask application designed for penetration testing practice. It contains deliberate security flaws including SQL injection, command injection, and XSS vulnerabilities.

**IMPORTANT**: This is a security training/testing application. Do NOT remove or "fix" the intentional vulnerabilities unless explicitly asked to do so. The vulnerabilities are the features.

## Running the Application

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
```
The app will start on `http://0.0.0.0:5000`

### Docker Deployment
```bash
# Build and run with docker-compose
docker-compose up -d

# Or build and run manually
docker build -t vulapp .
docker run -d -p 5000:5000 --name vulapp-container vulapp
```

## Architecture

### Application Structure
```
vulapp/
├── app.py              # Main Flask app initialization and request logging
├── config.py           # All configuration constants and credentials
├── database.py         # SQLite database initialization
├── auth.py             # Authentication decorators for route protection
├── utils.py            # Utility functions (OTP generation, echo, etc.)
├── schemas.py          # Marshmallow schemas for API validation
├── tracker.py          # File upload/download/delete tracking system
├── routes/
│   ├── web_routes.py   # HTML web endpoints (Blueprint: 'web')
│   └── api_routes.py   # JSON API endpoints (Blueprint: 'api')
├── templates/          # HTML templates for web routes
└── collections/
    └── bruno/          # Bruno API collection (served via /web/download/collection_bruno_v3.zip)
        ├── bruno.json
        ├── environments/local.bru
        ├── api/        # API endpoints (/api/tools/*, /api/v1/*)
        └── web/        # Web endpoints (/web/*) — file system routes excluded (intentionally hidden)
```

**Note on collections**: The Postman collection lives at `vulapp/collections/postman/collection.json` and is served via `/web/download/collection_postman.json`.

### Key Components

**Flask Blueprints**:
- `web_bp` (web_routes.py): Handles `/web/*` paths returning HTML
- `api_blp` (api_routes.py): Handles `/api/*` paths returning JSON, documented via Flask-Smorest/Swagger

**Authentication System** (auth.py):
Decorators that protect routes:
- `@requires_basic_auth`: HTTP Basic Auth with `admin`/`easypassword`
- `@requires_session`: Flask session with `logged_in: True`
- `@requires_2fa_session`: Flask session with `2fa_logged_in: True`
- `@requires_secret_header`: Checks for `secret-header: my-secret-header`
- `@requires_secret_cookie`: Checks for `secret-cookie=my-secret-cookie`
- `@requires_auth_token`: Validates Bearer token `Sf54F-/f#${wf}!*aR.y%`

**Database** (database.py):
- SQLite database (`pentest_target.db`) recreated on each startup
- Contains a `users` table with test accounts
- Uses raw SQL queries (intentionally vulnerable to injection)

**Request Logging** (app.py):
- All requests to `/web/welcome-*` and `/api/v1/*` are logged to stdout
- Logs include full request details (headers, params, session, cookies)

## Configuration Constants

All credentials and secrets are defined in `config.py`:
- Username: `admin`
- Password: `easypassword`
- TOTP Seed: `XVQ2UIGO75XRUKJO`
- Secret Header: `secret-header: my-secret-header`
- Secret Cookie: `secret-cookie: my-secret-cookie`
- Bearer Token: `Sf54F-/f#${wf}!*aR.y%`

These values are intentionally hardcoded for testing purposes.

## API Documentation & Collections

When the app is running:
- `/swagger-ui` - Interactive Swagger UI
- `/openapi.json` - OpenAPI 3.0.2 specification
- `/web/download/collection_bruno_v2.zip` - Download Bruno v2 collection (.bru files)
- `/web/download/collection_bruno_v3.zip` - Download Bruno v3 collection (.yml files)
- `/web/download/collection_bruno_v3_flat.zip` - Download Bruno v3 collection (flat, no root folder)
- `/web/download/collection_postman.json` - Download Postman collection (from `vulapp/collections/postman/`)

## Intentional Vulnerabilities

The application contains the following deliberate security flaws for training:

1. **SQL Injection**: `/web/login`, `/api/v1/users/<user_id>`, `/web/users`
2. **Command Injection**: `/web/ping` (via `host` query parameter)
3. **Reflected XSS**: `/web/welcome-simple`, `/web/welcome-2fa` (via username session variable)
4. **Session Management**: Simple session flags without proper validation

These vulnerabilities are documented in `README.md` and `ENDPOINTS.md`.

## File Upload/Download System

**These routes are intentionally hidden from users — do NOT add them to collections (Bruno/Postman) or expose them in README/index.html. Only people who discover them should know they exist.**

Routes: `/web/files` (browser UI), `/web/list-files` (JSON list), `/web/upload-file` (POST), `/web/upload-quota` (GET), `/web/download/<filename>`, `/web/delete/<filename>`.

Key behaviours (all in `tracker.py`):
- 50 files max per IP (`MAX_FILES_PER_IP`); returns 429 when exceeded
- Per-IP tracking persisted in `upload_tracker.json` (excluded from git): counts, timestamps, full history of uploads/downloads/deletions
- On filename collision, the existing file is renamed with a `YYYYMMDD_HHMMSS` timestamp suffix before the new file is saved
- IP detection respects `X-Forwarded-For` / `X-Real-IP` proxy headers
- Files stored in `uploads/` (excluded from git)

## Adding New Endpoints

### Web Routes (HTML)
Add to `vulapp/routes/web_routes.py`:
```python
@web_bp.route('/web/new-endpoint')
def new_endpoint():
    return render_template('template.html')
```

### API Routes (JSON)
Add to `vulapp/routes/api_routes.py` with Flask-Smorest:
```python
@api_blp.route('/v1/new-endpoint')
class NewEndpoint(MethodView):
    @api_blp.arguments(YourSchema)
    @api_blp.response(200, ResponseSchema)
    def post(self, args):
        return {"result": "data"}
```

Remember to create corresponding schemas in `schemas.py` for API validation.