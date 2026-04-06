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
