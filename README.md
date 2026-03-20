# Universal SQL API Gateway

The Universal SQL API Gateway is a high-performance, secure bridge designed to provide RESTful access to isolated SQL databases. Built with Flask and SQLAlchemy, it supports MySQL, PostgreSQL, and SQLite, offering an unified interface for dynamic database operations.

## Features

- **Multi-Database Support**: Dynamically load and manage multiple database connections via environment configuration.
- **Transactional Batch Execution**: Execute multiple SQL statements in a single atomic transaction with automatic rollback on failure.
- **Security-First Architecture**: Features integrated IP whitelisting, rate limiting, and read-only database enforcement.
- **Optimized for cPanel**: Architected for reliability in Phusion Passenger environments with efficient connection pooling and low memory overhead.
- **Automated Query Guard**: Automatically enforces result set limits on SELECT queries to prevent server resource exhaustion.
- **Sophisticated Metadata Discovery**: Endpoints for exploring database tables and column schemas with high-performance memory caching.

## Deployment

### Prerequisites
- Python 3.9+ (Python 3.13 recommended)
- Flask and SQLAlchemy
- Database drivers (PyMySQL, psycopg2-binary, etc.)

### Installation
1. Upload `app.py`, `passenger_wsgi.py`, and `requirements.txt` to the application directory.
2. Initialize the Python environment and install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the `.env` file according to the template provided below.
4. Set the application startup file to `passenger_wsgi.py` and the entry point to `application` in your server configuration.

## Configuration

Configuration is managed via environment variables in the `.env` file.

| Variable | Description |
| :--- | :--- |
| `API_KEY` | Master authentication key for all protected routes. |
| `ALLOWED_IPS` | Comma-separated list of permitted client IP addresses. |
| `DB_URL_{NAME}` | Connection string for a database alias. |
| `DB_MODE_{NAME}` | Access mode: `READWRITE` or `READONLY`. |
| `RATE_LIMIT` | Global request throttling (e.g., "60 per minute"). |
| `DB_POOL_SIZE` | Number of persistent connections per database engine. |
| `DB_MAX_OVERFLOW` | Maximum additional connections during peak load. |

## Authentication

All API endpoints, with the exception of `/health`, require a valid API key. The gateway supports two primary authentication methods:

1. **HTTP Header**: Provide the key via the `X-API-Key` header.
2. **Query Parameter**: Provide the key via the `api_key` parameter in the URL.

## API Endpoints

### Health Check
`GET /health`
Returns the operational status and access mode of all registered databases. No authentication required.

### Database Discovery
`GET /api/databases`
Retrieves a list of all configured database aliases and their respective modes.

### Table Enumeration
`GET /api/<db_alias>/tables`
Lists all tables within the specified database. Results are cached in memory for performance.

### Schema Inspection
`GET /api/<db_alias>/table/<table_name>/schema`
Provides detailed metadata for the specified table, including column types, nullability, and primary key status.

### Query Execution
`POST /api/<db_alias>/query`
Executes raw SQL queries passed in the request body.

#### Single Query
```json
{
  "query": "SELECT * FROM users WHERE id = :id",
  "params": {"id": 101}
}
```

#### Batch Transaction
```json
{
  "queries": [
    { "query": "INSERT INTO logs (event) VALUES (:e)", "params": {"e": "login"} },
    { "query": "UPDATE users SET last_login = NOW() WHERE id = :id", "params": {"id": 101} }
  ]
}
```

## Security and Performance

- **Rate Limiting**: Integrated request throttling to prevent denial-of-service attempts.
- **SQL Sanitization Check**: Enforces a strict `LIMIT 1000` on SELECT queries failing to provide their own limit.
- **Read-Only Enforcement**: Intercepts and rejects DDL and DML operations at the application layer for databases configured in `READONLY` mode.
- **Connection Reliability**: Implements `pool_pre_ping` to ensure stale database connections are automatically detected and replaced.
- **Logging**: Comprehensive structured logging of all requests, including execution times and SQL payloads, in `api_gateway.log`.
