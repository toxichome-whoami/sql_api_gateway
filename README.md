# Universal Secure SQL API Gateway

A powerful, highly configurable, and secure API Gateway built with Flask and SQLAlchemy. It acts as a bridge between your frontend/scripts and isolated SQL databases (MySQL, PostgreSQL, SQLite).

Designed specifically for easy deployment on cPanel via Phusion Passenger.

## Table of Contents
1. [Installation & Setup (cPanel)](#1-installation--setup-cpanel)
2. [How to Use the Features](#2-how-to-use-the-features)

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

# (Optional) Advanced Connection Pooling for High Concurrency
# Customize how many parallel connections the Gateway maintains to your DB to prevent overload
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20
```

### Step 5: Start the App
Click the **Restart** button in the cPanel Python App interface. Your API is now live!

## 2. How to Use the Features

All protected routes require your `API_KEY`. You can send it in two ways:
1.  **Header**: `X-API-Key: your_super_secret_api_key_here`
2.  **Query Parameter**: `?api_key=your_super_secret_api_key_here`

> [!TIP]
> **ModSecurity Bypass:** If your cPanel server uses strict ModSecurity WAF rules, sending complex API Keys (with symbols like `@`, `!`, `^`) via the `X-API-Key` HTTP Header will often trigger a **403 Forbidden** block. To easily bypass this, URL-encode your key and send it entirely via the Query Parameter instead!

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

### 🧹 5. Cache Management (Schema Refresh)
The gateway heavily caches database schemas in memory for high performance. If you create or modify tables, use this endpoint to force the gateway to refresh its memory.

*   **Endpoint:** `POST /api/cache/clear`

```bash
curl -X POST "https://yourdomain.com/api/cache/clear?api_key=YOUR_KEY"
```

### ⚡ 6. Execute Raw SQL Queries (Single or Transactional Batch)
Run single queries or full transactional batches.

**Example: Single SELECT Query**
```bash
curl -X POST "https://yourdomain.com/api/main/query?api_key=YOUR_KEY" \
     -H "Content-Type: application/json" \
     -d '{
           "query": "SELECT * FROM users WHERE status = :status",
           "params": {"status": "active"}
         }'
```
*Note: If no `LIMIT` is provided, the gateway automatically appends `LIMIT 1000` for server stability.*

**Example: Multi-Query Transactional Batch**
Perform multiple operations in a single atomic transaction. If *any* query fails, the entire batch is rolled back automatically.

```bash
curl -X POST "https://yourdomain.com/api/main/query?api_key=YOUR_KEY" \
     -H "Content-Type: application/json" \
     -d '{
           "queries": [
             { "query": "DROP TABLE IF EXISTS test_products" },
             { "query": "CREATE TABLE test_products (id INT, name VARCHAR(50))" },
             { "query": "INSERT INTO test_products (id, name) VALUES (1, :name)", "params": {"name": "Prod A"} }
           ]
         }'
```

### 🛡️ 7. Built-in Performance & Security Features
The Gateway automatically handles advanced security, caching, and performance tracking in the background:

*   **DDoS Protection (Rate Limiting)**: The gateway tracks incoming IPs and enforces a strict request limit (configurable via `RATE_LIMIT` in `.env`) using the `Flask-Limiter` engine.
*   **High-Concurrency Connection Pooling**: Automatically scales connections via `DB_POOL_SIZE` and `DB_MAX_OVERFLOW` to safely process massive parallel API loads without crashing your database.
*   **Instant Schema Caching**: All metadata endpoints (Tables & Schemas) utilize deep Python in-memory LRU caching. After the first call, they instantly return data from RAM.
*   **Comprehensive Audit Logging**: Every HTTP API request and every raw executed SQL query (along with its execution time) is comprehensively logged inside `api_gateway.log`.
*   **Safety SELECT Limits**: To prevent memory overload, any `SELECT` query lacking a `LIMIT` clause is automatically clamped to `LIMIT 1000`.
*   **Transactional Integrity**: Using the `queries` batch array ensures atomicity—if a multi-step query fails at step 50, the database is perfectly rolled back.
*   **Read-Only Defense**: If you set `DB_MODE_{NAME}=READONLY` in your `.env`, the gateway will intercept and immediately reject any `INSERT, UPDATE, DELETE, CREATE, DROP, ALTER` payload at the API level.
