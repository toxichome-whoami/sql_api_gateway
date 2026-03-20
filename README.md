# Universal Secure SQL API Gateway

A powerful, highly configurable, and secure API Gateway built with Flask and SQLAlchemy. It acts as a bridge between your frontend/scripts and isolated SQL databases (MySQL, PostgreSQL, SQLite).

Designed specifically for easy deployment on cPanel via Phusion Passenger.

## Table of Contents
1. [Installation & Setup (cPanel)](#1-installation--setup-cpanel)
2. [How to Use the Features](#2-how-to-use-the-features)

---

## 1. Installation & Setup (cPanel)

This API Gateway natively supports deployment using cPanel's **Setup Python App** feature.

### Step 1: Upload the Files
Upload the following core files to a directory on your cPanel server (e.g., `sql_api_gateway`):
*   `app.py`
*   `passenger_wsgi.py`
*   `requirements.txt`
*   `.env`

### Step 2: Create the Python App in cPanel
1. Navigate to your cPanel dashboard and click **Setup Python App**.
2. Click **Create Application**.
3. Set the following configurations:
    *   **Python version**: `3.9` to `3.13` (Highly recommended: `3.13`)
    *   **Application root**: The directory where you uploaded the files.
    *   **Application URL**: The domain/subdomain path for your API (e.g., `ipcatt.top/api`).
    *   **Application startup file**: `passenger_wsgi.py`
    *   **Application entry point**: `application`

### Step 3: Install Dependencies
1. Once the app is created, scroll down to the **Configuration files** section in the *Setup Python App* interface.
2. In the "Add another file" input, type `requirements.txt` and click **Add**.
3. Click **Run Pip Install**. This will install `Flask`, `SQLAlchemy`, and your database drivers.

### Step 4: Configure the Environment (`.env`)
Create a `.env` file in your application root folder based on `.env.example`:

```ini
# Generate a strong, random string for your API Key
API_KEY=your_super_secret_api_key_here

# (Optional) Restrict access to specific IPs
ALLOWED_IPS=192.168.1.100, 10.0.0.5

# Configure your databases dynamically.
# The {NAME} you use here is how you will call the database in the API URL.
DB_URL_MAIN=mysql+pymysql://user:pass@localhost/main_db
DB_URL_TEST=sqlite:///./test.db

# (Optional) Restrict databases to Read-Only mode to prevent accidental writes
DB_MODE_MAIN=READONLY
DB_MODE_TEST=READWRITE
```

### Step 5: Start the App
Click the **Restart** button in the cPanel Python App interface. Your API is now live!

## 2. How to Use the Features

All protected routes require your `API_KEY`. You can send it in two ways:
1.  **Header**: `X-API-Key: your_super_secret_api_key_here`
2.  **Query Parameter**: `?api_key=your_super_secret_api_key_here`

### 🩺 1. Global Health Check & Database Status
Ping all your databases instantly to see which ones are online, offline, or in read-only mode.

*   **Endpoint:** `GET /health`
*   *(No API Key Required)*

```bash
curl "https://yourdomain.com/health"
```

### 🗄️ 2. List Configured Databases
Returns all the database aliases you have set up in your `.env` file (`DB_URL_{NAME}`).

*   **Endpoint:** `GET /api/databases`

```bash
curl "https://yourdomain.com/api/databases?api_key=YOUR_KEY"
```

### 📋 3. Discover Database Tables
Get a list of all tables inside a specific database.

*   **Endpoint:** `GET /api/<db_name>/tables`
*   **Example:** For `DB_URL_MAIN` -> use `/api/main/tables`

```bash
curl "https://yourdomain.com/api/main/tables?api_key=YOUR_KEY"
```

### 🔍 4. Inspect Table Schema
Retrieve the exact column names, data types, and primary key constraints for a specific table.

*   **Endpoint:** `GET /api/<db_name>/table/<table_name>/schema`

```bash
curl "https://yourdomain.com/api/main/table/users/schema?api_key=YOUR_KEY"
```

### ⚡ 5. Execute Raw SQL Queries (Safe Parameter Binding)
Run DML (Select, Insert) and DDL (Create, Drop) queries dynamically.

*   **Endpoint:** `POST /api/<db_name>/query`
*   **Body Content-Type:** `application/json`

**Example: SELECT Query (Fetching Data)**
```bash
curl -X POST "https://yourdomain.com/api/main/query" \
     -H "X-API-Key: YOUR_KEY" \
     -H "Content-Type: application/json" \
     -d '{
           "query": "SELECT * FROM users WHERE status = :status LIMIT 10",
           "params": {"status": "active"}
         }'
```
*Note: Using `:status` in the query and supplying `"params": {"status": "active"}` completely protects you from SQL Injection!*

**Example: INSERT Query (Modifying Data)**
```bash
curl -X POST "https://yourdomain.com/api/test/query" \
     -H "X-API-Key: YOUR_KEY" \
     -H "Content-Type: application/json" \
     -d '{
           "query": "INSERT INTO logs (event, ip) VALUES (:event, :ip)",
           "params": {"event": "login", "ip": "192.168.1.1"}
         }'
```

### 🛡️ 6. Built-in Security & Monitoring Features
The Gateway automatically handles advanced security and performance tracking in the background:

*   **Execution Profiling**: Every JSON response includes `"execution_time_ms"`, showing exactly how fast the query ran on your database.
*   **Slow Query Logging**: If a query takes more than 1 second (1000ms), it is automatically recorded in the `api_gateway.log` file in your root folder.
*   **Multi-Statement Blocking**: Thwarts piggybacking SQL injection attacks by strictly blocking queries that attempt to run multiple separated SQL commands.
*   **CORS Ready**: Automatically handles `OPTIONS` preflight requests so you can call the API directly from a React, Vue, or Vanilla JS frontend application.
*   **Read-Only Defense**: If you set `DB_MODE_MAIN=READONLY` in your `.env`, the gateway will intercept and immediately reject any `INSERT, UPDATE, DELETE, CREATE, DROP, ALTER` payload aimed at that database.
