# VulApp Endpoint Documentation

This document provides a detailed overview of all endpoints available in the application, including authentication requirements, expected parameters, and potential responses.

## Web Endpoints (HTML UI)

| Endpoint | Method | Requirements | Description / Vulnerabilities | Status Codes |
| :--- | :---: | :--- | :--- | :--- |
| `/` | `GET` | None | Index page. | `200 OK` |
| `/web/login` | `GET`, `POST` | **Form Data**: `username`, `password` | Simple Login form. **Vulnerable to SQL Injection Bypass**. | `200 OK`, `302 Redirect` (Success), `401 Unauthorized` (Fail), `500 Error` |
| `/web/login-2fa` | `GET`, `POST` | **Form Data**: `username`, `password`, `otp` | 2FA Login with TOTP. Requires `XVQ2UIGO75XRUKJO` seed. | `200 OK`, `302 Redirect` (Success), `401 Unauthorized` (Fail), `404 Error` |
| `/web/welcome-basic-auth` | `GET` | **Basic Auth**: `admin` / `easypassword` | Protected welcome page using Basic Authentication. | `200 OK`, `401 Unauthorized` |
| `/web/welcome-simple` | `GET` | **Session**: `logged_in: True` | Welcome page for simple login. **Vulnerable to Reflected XSS** via username. | `200 OK`, `401 Unauthorized` |
| `/web/welcome-2fa` | `GET` | **Session**: `2fa_logged_in: True` | Welcome page for 2FA login. **Vulnerable to Reflected XSS** via username. | `200 OK`, `401 Unauthorized` |
| `/web/welcome-header` | `GET` | **Header**: `secret-header: my-secret-header` | Page accessible only with a specific secret header. | `200 OK`, `501 Not Implemented` (Fail) |
| `/web/welcome-cookie` | `GET` | None (Optional cookie check commented out) | Page that demonstrates CORS/XHR. | `200 OK` |
| `/web/ping` | `GET` | **Query Param**: `host` | Network utility. **Vulnerable to Command Injection** via `host`. | `200 OK` |
| `/web/users` | `GET` | **Query Param**: `search` | User search page. **Vulnerable to SQL Injection** via `search` parameter. | `200 OK` |
| `/web/guestbook` | `GET` | **Query Param**: `name` | Visitor guestbook. **Vulnerable to Reflected XSS** via `name` parameter. | `200 OK` |
| `/web/graphql` | `GET`, `POST` | **Query/Form Param**: `query` | GraphQL query interface. **Vulnerable to GraphQL Injection**, SQL Injection via GraphQL parameters, no depth limiting, introspection enabled, sensitive field exposure. | `200 OK` |
| `/web/files` | `GET` | None | Modern file browser with upload/download/delete functionality. | `200 OK` |
| `/web/upload-file` | `POST` | **Form Data**: `file` (multipart) | Upload file with 100MB size limit and 50 files/IP rate limiting. | `200 OK`, `400 Bad Request`, `413 Payload Too Large`, `429 Too Many Requests` |
| `/web/list-files` | `GET` | None | Returns JSON list of all uploaded files with metadata. | `200 OK` |
| `/web/upload-quota` | `GET` | None | Returns current upload quota for client IP. | `200 OK` |
| `/web/download/<filename>` | `GET` | **Path Variable**: `filename` | Download a file from uploads folder. | `200 OK`, `404 Not Found` |
| `/web/delete/<filename>` | `DELETE` | **Path Variable**: `filename` | Delete a file from uploads folder. | `200 OK`, `404 Not Found`, `500 Error` |
| `/web/logout` | `GET` | None | Clears the session and redirects to index. | `302 Redirect` |

## API Endpoints (`/api`)

| Endpoint | Method | Requirements | Description / Response | Status Codes | Headers |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `/api/tools/echo` | Any | None | Returns all request data (headers, params, body, etc.). | `200 OK` | None |
| `/api/tools/otp` | `GET` | **Query Param**: `seed_b32` or `seed_hex` (optional) | Generates TOTP code for the provided seed. | `200 OK`, `400 Error` | None |
| `/api/tools/otp` | `POST` | **Form Data**: `seed_b32` or `seed_hex` (optional) | Generates TOTP code for the provided seed. | `200 OK`, `400 Error` | None |
| `/api/v1/header-cookie` | `GET` | **Header**: `secret-header: my-secret-header`<br>**Cookie**: `secret-cookie=my-secret-cookie` | Returns request metadata. | `200 OK`, `501 Header Error`, `502 Cookie Error` | `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Credentials: True` |
| `/api/v1/header-cookie-auth` | `GET` | **Basic Auth**: `admin`/`easypassword`<br>**Header**: `secret-header: my-secret-header`<br>**Cookie**: `secret-cookie=my-secret-cookie` | Returns request metadata including auth. | `200 OK`, `401 Unauthorized`, `501/502 Error` | None |
| `/api/v1/users/<user_id>` | `GET` | **Path Variable**: `user_id` | User search API. **Vulnerable to SQL Injection** via `user_id`. | `200 OK`, `404 Not Found`, `500 DB Error` | None |
| `/api/v1/get-token` | `POST` | **JSON**: `{"auth": {"username": "admin", "password": "easypassword"}}` | Authenticates and returns a Bearer token. | `200 OK`, `400 Unauthorized` | None |
| `/api/v1/get-token-form` | `POST` | **Form Data**: `username=admin&password=easypassword` | Authenticates via form data and returns a Bearer token. | `200 OK`, `400 Unauthorized` | None |
| `/api/v1/is-valid-token` | `GET`, `POST` | **Header**: `token: Bearer Sf54F-/f#${wf}!*aR.y%` | Validates the provided Bearer token. | `200 OK`, `501 Invalid Token` | None |

## File Upload System

The file upload system tracks all uploads, downloads, and deletions per IP address in `upload_tracker.json`:

- **Rate Limiting:** Maximum 50 files per IP address
- **File Size Limit:** 100MB per file
- **Collision Handling:** Existing files are renamed with timestamp (e.g., `file_20251231_151050.ext`)
- **Tracking:** All operations (upload/download/delete) are logged with filename, size, and timestamp
- **Storage:** Files stored in `uploads/` directory

### Upload Quota Response (`/web/upload-quota`)
```json
{
  "uploads_used": 5,
  "uploads_limit": 50,
  "uploads_remaining": 45,
  "percentage": 10.0
}
```

## API Response Examples

### Successful Authentication (`/api/v1/get-token` and `/api/v1/get-token-form`)
Returns a `200 OK` status with the following JSON structure:
```json
{
  "reply": {
    "token": "Sf54F-/f#${wf}!*aR.y%",
    "prefix": "Bearer"
  }
}
```

## API Documentation

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/swagger-ui` | `GET` | Interactive Swagger UI for API testing. |
| `/openapi.json` | `GET` | Raw OpenAPI 3.0.2 specification. |

## Authentication Credentials

- **Username:** `admin`
- **Password:** `easypassword`
- **TOTP Seed:** `XVQ2UIGO75XRUKJO`
- **Secret Header:** `secret-header: my-secret-header`
- **Secret Cookie:** `secret-cookie: my-secret-cookie`
- **Bearer Token Header:** `token: Bearer Sf54F-/f#${wf}!*aR.y%`
