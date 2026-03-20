
import os
import logging
import time
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError
import functools
from dotenv import load_dotenv

# --- Initialization ---
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(
    filename=os.path.join(PROJECT_ROOT, 'api_gateway.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
app = Flask(__name__)
API_KEY = os.environ.get("API_KEY")

# Global Rate Limiting
def get_real_ip():
    forwarded = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
    return forwarded.split(",")[0].strip() or "127.0.0.1"

limiter = Limiter(
    get_real_ip,
    app=app,
    default_limits=[os.environ.get("RATE_LIMIT", "1000 per minute")],
    storage_uri="memory://"
)

# --- Advanced Security Configuration ---
# 1. IP Whitelisting: Comma-separated list of safe IPs. If empty, all IPs allowed.
ALLOWED_IPS = [ip.strip() for ip in os.environ.get("ALLOWED_IPS", "").split(",") if ip.strip()]

# 2. CORS Allow Origin: Set specific frontend domains, default is all
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

@app.after_request
def apply_security_headers_and_log(response):
    """Apply strict security headers, CORS, and log every request."""
    response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    
    # Security definitions
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Comprehensive Request Logging
    forwarded = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
    client_ip = forwarded.split(",")[0].strip() or "Unknown"
    logger.info(f"[{client_ip}] {request.method} {request.path} - HTTP {response.status_code}")
    
    return response

@app.before_request
def check_ip_whitelist():
    """Block IPs that are not explicitly whitelisted (if whitelist is active)."""
    if ALLOWED_IPS:
        forwarded = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
        client_ip = forwarded.split(",")[0].strip()
        if client_ip and client_ip not in ALLOWED_IPS:
            logger.warning(f"Blocked request from non-whitelisted IP: {client_ip}")
            abort(403, description="Access forbidden: Your IP is not permitted.")

def verify_api_key():
    """Verify Master Key from X-API-Key header OR api_key query parameter."""
    if request.method == "OPTIONS":
        return # Allow CORS preflight

    token = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not token or token != API_KEY:
        logger.warning(f"Unauthorized API access attempt. Invalid/Missing API Key.")
        abort(401, description="Invalid or missing API Key")

@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler hiding internal stack traces from clients."""
    status_code = getattr(e, 'code', 500)
    # Hide internal details for 500 errors to prevent info leakage
    if status_code == 500:
        logger.exception("Internal Server Error")
        description = "Internal Server Error"
    else:
        description = getattr(e, 'description', "Error")
    return jsonify({"error": description}), status_code

# --- Database Management ---
db_engines = {}
db_permissions = {} # Cache for Read-Only vs Read-Write states

def get_engine(db_name: str):
    """Retrieve or initialize a SQLAlchemy engine."""
    db_name = db_name.upper()
    if db_name in db_engines:
        return db_engines[db_name]

    connection_string = os.environ.get(f"DB_URL_{db_name}")
    if not connection_string:
        abort(404, description=f"Database '{db_name}' not configured.")

    # Apply database operation mode (READWRITE by default)
    mode = os.environ.get(f"DB_MODE_{db_name}", "READWRITE").upper()
    db_permissions[db_name] = mode

    try:
        # Advanced Connection Pooling for high concurrency and stability
        engine = create_engine(
            connection_string, 
            pool_pre_ping=True,       # Prevents 'MySQL server has gone away'
            pool_size=int(os.environ.get("DB_POOL_SIZE", 10)),     # Base active connections
            max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", 20)), # Spikes allowed
            pool_recycle=1800,        # Recycle connections every 30 mins
            pool_timeout=15           # Drop overloaded requests fast to prevent piling up
        )
        db_engines[db_name] = engine
        return engine
    except Exception as e:
        logger.error(f"Failed to connect to {db_name}: {str(e)}")
        abort(500, description="Database initialization failed.")

# --- Endpoints ---

@app.route("/", methods=["GET", "OPTIONS"], strict_slashes=False)
def index():
    return jsonify({
        "status": "Gateway online",
        "security": "Maximum",
        "ip_whitelisting": "Enabled" if ALLOWED_IPS else "Disabled"
    })

@app.route("/health", methods=["GET", "OPTIONS"], strict_slashes=False)
def health_check():
    """Monitor connectivity to all databases and return statuses."""
    status = {"status": "ok", "databases": {}}
    for key in os.environ:
        if key.startswith("DB_URL_"):
            name = key.replace("DB_URL_", "").lower()
            try:
                engine = get_engine(name)
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                mode = db_permissions.get(name.upper(), "UNKNOWN")
                status["databases"][name] = {"status": "connected", "mode": mode}
            except Exception:
                status["status"] = "degraded"
                status["databases"][name] = {"status": "offline"}
    return jsonify(status)

@app.route("/api/databases", methods=["GET", "OPTIONS"], strict_slashes=False)
def list_databases():
    verify_api_key()
    dbs = []
    for k in os.environ:
        if k.startswith("DB_URL_"):
            db_name = k.replace("DB_URL_", "").lower()
            get_engine(db_name) # Ensure permissions cache is populated
            dbs.append({
                "name": db_name,
                "mode": db_permissions.get(db_name.upper(), "READWRITE")
            })
    return jsonify({"configured_databases": dbs})

@functools.lru_cache(maxsize=32)
def _fetch_table_names(db_name):
    engine = get_engine(db_name)
    return inspect(engine).get_table_names()

@functools.lru_cache(maxsize=128)
def _fetch_table_schema(db_name, table_name):
    engine = get_engine(db_name)
    columns = inspect(engine).get_columns(table_name)
    return [{"name": c['name'], "type": str(c['type']), "nullable": c['nullable']} for c in columns]

@app.route("/api/<db_name>/tables", methods=["GET", "OPTIONS"], strict_slashes=False)
def list_tables(db_name):
    verify_api_key()
    return jsonify({"database": db_name, "tables": _fetch_table_names(db_name)})

@app.route("/api/<db_name>/table/<table_name>/schema", methods=["GET", "OPTIONS"], strict_slashes=False)
def get_table_schema(db_name, table_name):
    verify_api_key()
    return jsonify({"database": db_name, "table": table_name, "schema": _fetch_table_schema(db_name, table_name)})

@app.route("/api/cache/clear", methods=["POST", "OPTIONS"], strict_slashes=False)
def clear_cache():
    """Manually flush the LRU metadata cache so newly created tables appear instantly."""
    if request.method == "OPTIONS":
        return jsonify({})
    verify_api_key()
    _fetch_table_names.cache_clear()
    _fetch_table_schema.cache_clear()
    return jsonify({"success": True, "message": "Schema cache completely flushed."})

@app.route("/api/<db_name>/query", methods=["POST", "OPTIONS"], strict_slashes=False)
def execute_query(db_name):
    """Execute single or multiple SQL queries within a secure transaction scope."""
    if request.method == "OPTIONS":
        return jsonify({}) # Required for CORS

    verify_api_key()

    data = request.get_json()
    if not data:
        abort(400, description="Payload must contain JSON.")

    # Parse Payload Batch
    queries = []
    if 'queries' in data and isinstance(data['queries'], list):
        queries = data['queries']
    elif 'query' in data:
        queries = [{"query": data['query'], "params": data.get('params', {})}]
    else:
        abort(400, description="Payload must contain 'query' string or 'queries' array.")

    engine = get_engine(db_name)
    start_time = time.time()
    
    # Pre-flight Validation & Auto-Clamping Loop
    for q in queries:
        query_str = q.get('query', '').strip()
        
        # Security Rule 1: Prevent basic stacked queries INSIDE single entries
        if ";" in query_str.rstrip(";"):
            logger.warning(f"Blocked inline multi-statement query attempt.")
            abort(400, description="Multiple SQL statements restricted per field. Use 'queries' array for transactions.")

        # Security Rule 2: Database Mode Enforcement
        is_modifying = query_str.upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "TRUNCATE", "REPLACE"))
        if is_modifying and db_permissions.get(db_name.upper()) == "READONLY":
            logger.warning(f"Blocked write attempt on READONLY database {db_name}")
            abort(403, description=f"Database '{db_name}' is locked in READONLY mode.")
            
        # Security Rule 3: Forced Safe Pagination
        if query_str.upper().startswith("SELECT") and "LIMIT" not in query_str.upper():
            query_str = query_str.rstrip(";") + " LIMIT 1000"
            logger.info("Automatically clamped unpaginated SELECT query with LIMIT 1000")
            
        q['safe_query'] = query_str
        q['is_modifying'] = is_modifying

    results = []
    try:
        # Transaction Context Manager - Error in any query rolls back the ENTIRE batch instantly
        with engine.begin() as conn:
            for q in queries:
                sql = text(q['safe_query'])
                result = conn.execute(sql, q.get('params', {}))
                
                if result.returns_rows:
                    rows = [dict(row._mapping) for row in result.fetchall()]
                    results.append({"rowcount": len(rows), "data": rows})
                elif q['is_modifying']:
                    results.append({"rowcount": result.rowcount})
                else:
                    results.append({"message": "Query executed successfully."})

        exec_time_ms = round((time.time() - start_time) * 1000, 2)
        
        logger.info(f"Transaction on '{db_name}' completed ({len(queries)} ops) in {exec_time_ms}ms")
        
        if exec_time_ms > 1000:
            logger.warning(f"Slow Transaction Alert '{db_name}' ({exec_time_ms}ms) across {len(queries)} operations.")

        # Backward compatibility wrapper for single-query requests
        if 'query' in data and not 'queries' in data:
            final_res = results[0]
            final_res['success'] = True
            final_res['execution_time_ms'] = exec_time_ms
            return jsonify(final_res)
            
        return jsonify({
            "success": True, 
            "execution_time_ms": exec_time_ms,
            "transaction_count": len(results),
            "results": results
        })

    except SQLAlchemyError as e:
        logger.error(f"Execution Error: {str(e)}")
        # Client intentionally receives a blanket message to prevent exposing exact internal DB states if a transaction fails
        abort(400, description="Database Execution Error. The entire query batch has been successfully isolated and rolled back.")

if __name__ == "__main__":
    app.run(debug=True)
