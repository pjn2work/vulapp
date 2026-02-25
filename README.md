# VulWeb - Pentest Target Lab

A vulnerable Flask application designed for penetration testing practice.

## Lab Credentials and Configuration

To perform your pentests, use the following known values:

*   **Username:** `admin`
*   **Password:** `easypassword`
*   **TOTP Seed:** `XVQ2UIGO75XRUKJO`
*   **Secret Header:** `secret-header: my-secret-header`
*   **Secret Cookie:** `secret-cookie: my-secret-cookie`

---

## Endpoints and Requirements

### Web Authentication Forms
*   **`/web/login`**: Simple Login form. Vulnerable to **SQL Injection Bypass**.
*   **`/web/login-2fa`**: Login form with TOTP. Requires User + Pass + OTP code.
*   **`/web/logout`**: Clears the current session.

### Protected "Welcome" Pages
These pages require specific authentication or headers to access. All `/web/welcome-` requests are logged to `welcome_requests.log` and the console.

| Path | Requirement |
| :--- | :--- |
| `/web/welcome-basic-auth` | **Basic Auth** (`admin` / `easypassword`) |
| `/web/welcome-simple` | **Session variable** `logged_in: True` (obtained via `/web/login`) |
| `/web/welcome-2fa` | **Session variable** `2fa_logged_in: True` (obtained via `/web/login-2fa`) |
| `/web/welcome-header` | **HTTP Header**: `secret-header: my-secret-header` |
| `/web/welcome-cookie` | **Cookie**: `secret-cookie=my-secret-cookie` |

### Vulnerable Tools
*   **`/api/v1/users/<user_id>`**: User search API. Vulnerable to **SQL Injection** via the `user_id` path parameter.
*   **`/web/ping`**: Network utility. Vulnerable to **Command Injection** via the `host` query parameter.

### API Endpoints
*   **`/swagger-ui`**: Interactive Swagger documentation for the API.
*   **`/openapi.json`**: Raw OpenAPI specification.
*   **`/api/tools/echo`**: Echos back all request data (headers, params, body, cookies, session) in JSON format.
*   **`/api/tools/otp`**: TOTP utility.
    *   **Usage:** `GET` (query params) or `POST` (form data) with `seed` parameter.
    *   **Returns:** JSON containing current code, time remaining, and the seed.
*   **`/api/v1/header-cookie`**: API protected by both a secret header and a secret cookie.
*   **`/api/v1/header-cookie-auth`**: API protected by Basic Auth, a secret header, and a secret cookie.
*   **`/api/v1/users/<user_id>`**: API version of the user search tool. Vulnerable to **SQL Injection**.

---

## Logging and Monitoring

### File Logs
Requests to `/web/welcome-` or `/api/v1/` endpoints are printed to stdout.

---

## Setup and Execution

### Local Development
1.  **Install Dependencies:** `pip install -r requirements.txt`
2.  **Run:** `python app.py` (Starts on `http://0.0.0.0:5000`)

### Docker Deployment
1.  **Build:** `docker build -t vulapp .`
2.  **Run:** `docker run -d -p 5000:5000 --name vulapp-container vulapp`
3.  **Compose:** `docker-compose up -d`
