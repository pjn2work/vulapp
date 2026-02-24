# VulWeb - Pentest Target Lab

A vulnerable Flask application designed for penetration testing practice.

## Project Structure
- `app.py`: Main Flask application.
- `requirements.txt`: Python dependencies (`flask`, `pyotp`).
- `templates/`: HTML templates for the web pages.
- `pentest_target.db`: SQLite database (auto-generated on first run).

## Global Security Controls
To access certain protected or vulnerable pages, you may need to satisfy the following:

1.  **Mandatory Header:** Required only for "Original Vulnerable Tools" (User Search and Ping Tool):
    `secret-header: my-secret-header`
2.  **Basic Auth:**
    - **Username:** `admin`
    - **Password:** `easypassword`
3.  **2FA (TOTP):** A secondary login step using the seed: `123456QA`.
4.  **Cookie:** A `tracking_id` cookie is set upon the first visit to the index page.

## Authentication Scenarios

### 1. Simple Login (User + Pass)
- **Path:** `/web/login`
- **Vulnerability:** **SQL Injection Login Bypass**.
- **Payload:** Username: `' OR 1=1 --` / Password: `anything`
- **Result:** Success redirects to `/web/welcome-simple` which says "You are welcome!" and is vulnerable to **Reflected XSS**.

### 2. Full 2FA Login (User + Pass + TOTP)
- **Path:** `/web/login-2fa`
- **Requirements:** Username, Password, and TOTP code (Seed: `123456QA`).
- **Result:** Success redirects to a 2FA-secured "You are welcome!" page.

### 3. Basic Auth Section
- **Path:** `/web/basic-auth`
- **Authentication:** Uses browser-native Basic Access Authentication.
- **Result:** Displays a welcome message upon successful authentication.

## Original Vulnerable Tools

### 1. User Search (SQL Injection)
- **Path:** `/web/users`
- **Requirements:** Mandatory `secret-header`.
- **Vulnerability:** **SQL Injection** via the `search` parameter.

### 2. Ping Tool (Command Injection)
- **Path:** `/web/ping`
- **Requirements:** Mandatory `secret-header`.
- **Vulnerability:** **Command Injection**.
- **Payload:** `127.0.0.1; whoami`
- **Result:** Executes commands on the server.

## Setup and Execution

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Server:**
    ```bash
    python app.py
    ```
    The server will start on `http://127.0.0.1:5000`.

## Docker Setup

### 1. Build the Image
From the project root directory, run:
```bash
docker build -t vulweb .
```

### 2. Run the Container
To start the container and map port 5000:
```bash
docker run -d -p 5000:5000 --name vulweb-container vulweb
```
The app will be accessible at `http://localhost:5000`.

### 3. Manage with Portainer
If you have Portainer installed, you can monitor, start, and stop this container via the web interface:
1. Open Portainer in your browser (usually `https://<your-ip>:9443`).
2. Go to **Containers**.
3. You will see `vulweb-container` in the list. Use the **Start**, **Stop**, or **Restart** buttons to manage it.
4. Click on the **Logs** icon to see the Flask output in real-time.

## Comparing HTTP vs HTTPS

Since both `http://` and `https://` are now active, you can observe the difference in security by sniffing your own traffic.

### 1. Sniff HTTP Traffic (Unencrypted)
In a separate terminal, run:
```bash
sudo tcpdump -i any port 80 -A
```
Now, make a request to `http://vulweb.pjn.ddns.net`. You will see all your headers, cookies, and data in **plain text**.

### 2. Sniff HTTPS Traffic (Encrypted)
In a separate terminal, run:
```bash
sudo tcpdump -i any port 443 -A
```
Now, make a request to `https://vulweb.pjn.ddns.net`. You will see only **encrypted gibberish**, as the TLS layer hides the data from sniffers.


## API Debugging
### API Echo Endpoint
- **Path:** `/api-echo`
- **Purpose:** Reflects all request data for debugging and observation.
- **Fields:**
    - `scheme`: The protocol used (`http` or `https`).
    - `is_https`: Boolean indicating if the connection is secure.
    - `full_url`: The complete URL of the request.
    - `headers`: Dictionary of all request headers.
    - `method`: The HTTP method used (GET, POST, etc.).
