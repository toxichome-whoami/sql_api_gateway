# Universal SQL API Gateway

The Universal SQL API Gateway is a high-performance, professional-grade bridge designed to provide secure RESTful access to isolated SQL databases. Developed with Flask and SQLAlchemy, it supports MySQL, PostgreSQL, and SQLite, offering a unified interface for dynamic database operations across distributed environments.

## Features

- **Multi-Database Registry**: Dynamically load and manage multiple database connections through environment-based alias configuration.
- **Transactional Batch Execution**: Support for executing multiple SQL statements within a single atomic transaction, ensuring data integrity with automatic rollback on failure.
- **RBAC and Multi-Key Authentication**: Advanced authentication supporting both master API keys and multi-client JSON-based configurations with role-based access control (READONLY, READWRITE, ADMIN).
- **Security Engineering**: Integrated IP allowlisting, global request throttling (rate limiting), and application-level read-only enforcement.
- **Automated Query Guard**: Proactive enforcement of result set limits on SELECT queries to prevent resource exhaustion and ensure consistent response times.
- **Metadata Inspection**: Specialized endpoints for discovering database structures, including table enumeration and detailed column schema inspection.

## Deployment

### Prerequisites
- Python 3.9 or higher (Python 3.13 recommended for performance)
- Flask and Flask-Limiter
- SQLAlchemy 2.0+
- Appropriate database drivers (e.g., PyMySQL, psycopg2-binary, aiosqlite)

### Installation
1. Deploy `app.py`, `passenger_wsgi.py`, and `requirements.txt` to the application directory on the server.
2. Install the necessary dependencies via the standard package manager:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the `.env` file based on the technical specifications below.
4. Set the application startup file to `passenger_wsgi.py` in your web server or cPanel configuration.

## Configuration Technical Reference

Configuration is managed via the `.env` file using the following schema:

| Variable | Type | Description |
| :--- | :--- | :--- |
| `API_KEY` | String | Master authentication key for all protected routes. |
| `API_KEYS_JSON` | JSON | Advanced multi-client configuration (e.g., `{"client1": {"key": "abc", "role": "READONLY"}}`). |
| `ALLOWED_IPS` | CSV | Comma-separated list of permitted client IP addresses. |
| `DB_URL_{ALIAS}` | URI | SQLAlchemy connection string for a specific database alias. |
| `DB_MODE_{ALIAS}` | Enum | Access mode for the specific database: `READWRITE` or `READONLY`. |
| `RATE_LIMIT` | String | Global request throttling policy (e.g., "120 per minute"). |
| `QUERY_TIMEOUT_SECONDS` | Integer | Global timeout for SQL execution. |
| `DB_POOL_SIZE` | Integer | Connection pool size for each database engine. |
| `LOG_LEVEL` | Enum | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

## Authentication and Security

### Authentication Methods
The gateway requires a valid API key for all routes except `/health`. Keys can be provided through:
1. **HTTP Header**: Using the `X-API-Key` field.
2. **Query Parameter**: Using the `api_key` field in the request URL.

### Security Controls
- **Standardized Limits**: All SELECT queries are automatically appended with `LIMIT 1000` if no limit is specified in the SQL.
- **Write Keyword Protection**: Operations including `DROP`, `ALTER`, and `TRUNCATE` are strictly validated against the database and client access modes.
- **Audit Logging**: All database interactions are recorded with client IP, execution time, and SQL payload for forensic and performance analysis.

## API Specification

### Operational Health
`GET /health`  
Returns the status, access mode, and connectivity of all registered database aliases.

### Database Enumeration
`GET /api/databases`  
Retrieves a comprehensive list of configured databases available for the authenticated client.

### Table Discovery
`GET /api/<db_alias>/tables`  
Lists all available tables within the specified database registry.

### Schema Inspection
`GET /api/<db_alias>/table/<table_name>/schema`  
Provides technical metadata for the specified table, including column types, nullability, and primary key constraints.

### Data Interaction
`POST /api/<db_alias>/query`  
Executes SQL queries provided in the request body. Supports both single queries and batch transactions.

#### Single Query Payload
```json
{
  "query": "SELECT * FROM portfolio_data WHERE category = :cat",
  "params": {"cat": "active"}
}
```

#### Batch Transaction Payload
```json
{
  "queries": [
    { "query": "INSERT INTO logs (action) VALUES (:a)", "params": {"a": "update"} },
    { "query": "UPDATE stats SET hits = hits + 1 WHERE id = :id", "params": {"id": 5} }
  ]
}
```

## Performance Diagnostics

Execution performance is logged systematically. Developers can utilize the provided `test_v2.js` Node.js script to perform automated integration testing and connection validation across all registered registries.
