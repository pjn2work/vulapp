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
| `/web/logout` | `GET` | None | Clears the session and redirects to index. | `302 Redirect` |

## API Endpoints (`/api`)

| Endpoint | Method | Requirements | Description / Response | Status Codes | Headers |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `/api/tools/echo` | Any | None | Returns all request data (headers, params, body, etc.). | `200 OK` | None |
| `/api/tools/otp` | `GET` | **Query Param**: `seed` (optional) | Generates TOTP code for the provided seed. | `200 OK`, `400 Error` | None |
| `/api/tools/otp` | `POST` | **Form Data**: `seed` (optional) | Generates TOTP code for the provided seed. | `200 OK`, `400 Error` | None |
| `/api/v1/header-cookie` | `GET` | **Header**: `secret-header: my-secret-header`<br>**Cookie**: `secret-cookie=my-secret-cookie` | Returns request metadata. | `200 OK`, `501 Header Error`, `502 Cookie Error` | `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Credentials: True` |
| `/api/v1/header-cookie-auth` | `GET` | **Basic Auth**: `admin`/`easypassword`<br>**Header**: `secret-header: my-secret-header`<br>**Cookie**: `secret-cookie=my-secret-cookie` | Returns request metadata including auth. | `200 OK`, `401 Unauthorized`, `501/502 Error` | None |
| `/api/v1/users/<user_id>` | `GET` | **Path Variable**: `user_id` | User search API. **Vulnerable to SQL Injection** via `user_id`. | `200 OK`, `404 Not Found`, `500 DB Error` | None |

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
