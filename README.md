# Universal Secure SQL API Gateway

A powerful, highly configurable, and enterprise-grade secure API Gateway built with Flask and SQLAlchemy. It acts as a bridge between your frontend/scripts and isolated SQL databases (MySQL, PostgreSQL, SQLite), providing a unified RESTful interface.

Designed specifically for high-performance and low-RAM footprint on cPanel hosting via Phusion Passenger.

## ✨ Core Features
- **🚀 Standardized Auth**: Supports Professional `Bearer Token` authentication (RFC standard).
- **🛡️ Firewall Resilient**: Multi-header support (`X-API-Key`, `X-SQL-Auth`) and URL parameter support to bypass restrictive WAFs (ModSecurity).
- **⚡ Atomic Transactions**: Run single queries or full transactional batches with automatic rollback on failure.
- **📂 Schema Exploration**: In-memory cached endpoints to list tables and column metadata.
- **🚥 Rate Limiting**: Built-in DDoS protection via `Flask-Limiter`.
- **🍃 Resource Efficient**: Optimized for low-RAM environments like cPanel using intelligent connection cleanup.
- **🔒 Security by Design**: Forced `LIMIT 1000` on SELECTs and strict Read-Only database enforcement.

---

## 📅 1. Installation & Setup (cPanel)

### Step 1: Upload the Files
Upload the following core files to your application directory:
*   `app.py`
*   `passenger_wsgi.py`
*   `requirements.txt`
*   `.env`

### Step 2: Create the Python App in cPanel
1. Navigate to **Setup Python App** in your cPanel dashboard.
2. Click **Create Application** and set:
    *   **Python version**: `3.13` (Recommended)
    *   **Application root**: The folder path (e.g., `api_gateway`).
    *   **Application URL**: Your target URL (e.g., `domain.com/sql-bridge`).
    *   **Application startup file**: `passenger_wsgi.py`
    *   **Application entry point**: `application`

### Step 3: Install Dependencies
1. Scroll to the **Configuration files** section.
2. Add `requirements.txt` and click **Add**.
3. Click **Run Pip Install**.

### Step 4: Configure the Environment (`.env`)
Create your `.env` file with these optimized production settings:

```ini
API_KEY=your_long_secure_key_here
ALLOWED_IPS=127.0.0.1, 103.137.7.100

# Rate Limit (Format: "count per time-unit")
RATE_LIMIT=120 per minute

# Database 1: Main (Full Access)
DB_URL_MAIN=mysql+pymysql://user:pass@localhost/main_db
DB_MODE_MAIN=READWRITE

# Database 2: Archive (Read Only Protection)
DB_URL_HISTORY=postgresql://user:pass@external-db.com/history
DB_MODE_HISTORY=READONLY

# Performance Tuning for cPanel
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=10
LOG_FILE=api_gateway.log
LOG_LEVEL=INFO
```

---

## 🗝️ 2. Authentication Methods

The gateway supports three ways to authenticate. If your server firewall (ModSecurity) blocks one, simply switch to another:

| Method | Recommendation | Header / Param |
| :--- | :--- | :--- |
| **Bearer Token** | ⭐ **Best/Standard** | `Authorization: Bearer <YOUR_KEY>` |
| **URL Parameter** | 🛡️ **Firewall Proof** | `?api_key=<YOUR_KEY>` |
| **Custom Header** | Alternative | `X-SQL-Auth: <YOUR_KEY>` or `X-API-Key: <YOUR_KEY>` |

---

## 📡 3. API Documentation

### 🟢 GET /health
Verify the status of all configured databases.
*   **Auth:** *Not Required (Public)*
*   **Response:** `{"status": "ok", "databases": {"main": {"status": "online", "mode": "READWRITE"}}}`

### 🗄️ GET /api/databases
List all database aliases configured in your `.env`.

### 📋 GET /api/<db_alias>/tables
List all table names inside a specific database.

### 🔍 GET /api/<db_alias>/table/<table_name>/schema
Get column names, types, and primary key metadata for a table.

### ⚡ POST /api/<db_alias>/query
Execute SQL queries using the JSON engine.

**Example: Transactional Batch (Write + Read)**
```json
{
  "queries": [
    { "query": "DROP TABLE IF EXISTS demo" },
    { "query": "CREATE TABLE demo (id INT, val TEXT)" },
    { "query": "INSERT INTO demo (id, val) VALUES (:id, :val)", "params": {"id": 1, "val": "Test"} },
    { "query": "SELECT * FROM demo" }
  ]
}
```

---

## 🛡️ 4. Security & Safety Guards

1.  **Transactional Integrity**: If `queries` array is used, all steps are atomic. One failure = entire rollback.
2.  **Safety SELECT Limits**: Any `SELECT` query without an explicit `LIMIT` will be automatically clamped to `LIMIT 1000` to prevent RAM exhaustion and crashing the Python worker.
3.  **Read-Only Mode**: Setting `DB_MODE=READONLY` blocks `INSERT, UPDATE, DELETE, CREATE, DROP, ALTER` at the API Gateway level (before they even hit the database).
4.  **MetaData Caching**: Database structure (Tables/Schemas) is cached in RAM using an LRU cache. Use `POST /api/cache/clear` to refresh if you change your DB structure manually.
5.  **IP Allowlist**: Restrict the entire Gateway to specific IP addresses using `ALLOWED_IPS` in `.env`.

---

✨ **Your Gateway is now ready for Professional Deployment.** ✨
