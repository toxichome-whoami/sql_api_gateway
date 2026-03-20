
import os
import logging
import time
from flask import Flask, request, jsonify, abort
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError
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
        engine = create_engine(connection_string, pool_pre_ping=True)
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

@app.route("/api/<db_name>/tables", methods=["GET", "OPTIONS"], strict_slashes=False)
def list_tables(db_name):
    verify_api_key()
    engine = get_engine(db_name)
    tables = inspect(engine).get_table_names()
    return jsonify({"database": db_name, "tables": tables})

@app.route("/api/<db_name>/table/<table_name>/schema", methods=["GET", "OPTIONS"], strict_slashes=False)
def get_table_schema(db_name, table_name):
    verify_api_key()
    engine = get_engine(db_name)
    columns = inspect(engine).get_columns(table_name)
    schema = [{"name": c['name'], "type": str(c['type']), "nullable": c['nullable']} for c in columns]
    return jsonify({"database": db_name, "table": table_name, "schema": schema})

@app.route("/api/<db_name>/query", methods=["POST", "OPTIONS"], strict_slashes=False)
def execute_query(db_name):
    """Execute SQL with advanced security mapping and timing."""
    if request.method == "OPTIONS":
        return jsonify({}) # Required for CORS

    verify_api_key()

    data = request.get_json()
    if not data or 'query' not in data:
        abort(400, description="Payload must contain 'query'.")

    query_str = data.get('query').strip()
    params = data.get('params', {})

    # Security Rule 1: Prevent basic stacked queries
    if ";" in query_str.rstrip(";"):
        logger.warning(f"Blocked multi-statement query attempt.")
        abort(400, description="Multiple SQL statements are restricted.")

    engine = get_engine(db_name)
    is_modifying = query_str.upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "TRUNCATE", "REPLACE"))

    # Security Rule 2: Database Mode Enforcement
    if is_modifying and db_permissions.get(db_name.upper()) == "READONLY":
        logger.warning(f"Blocked write attempt on READONLY database {db_name}")
        abort(403, description=f"Database '{db_name}' is locked in READONLY mode.")

    # Start execution timer
    start_time = time.time()

    try:
        with engine.connect() as conn:
            sql = text(query_str)
            result = conn.execute(sql, params)

            exec_time_ms = round((time.time() - start_time) * 1000, 2)

            # Log EVERY query executed
            logger.info(f"Query on '{db_name}' ({exec_time_ms}ms): {query_str[:150]}")

            # Warning for slow queries (>1000ms)
            if exec_time_ms > 1000:
                logger.warning(f"Slow Query Alert '{db_name}' ({exec_time_ms}ms): {query_str[:150]}...")

            if is_modifying:
                conn.commit()
                return jsonify({
                    "success": True,
                    "rowcount": result.rowcount,
                    "execution_time_ms": exec_time_ms
                })

            if result.returns_rows:
                rows = [dict(row._mapping) for row in result.fetchall()]
                return jsonify({
                    "success": True,
                    "rowcount": len(rows),
                    "data": rows,
                    "execution_time_ms": exec_time_ms
                })

            return jsonify({"success": True, "message": "Query executed.", "execution_time_ms": exec_time_ms})

    except SQLAlchemyError:
        # Hide SQL syntax errors from response to prevent mapping attacks
        abort(400, description="Database Execution Error. Check syntax and constraints.")

if __name__ == "__main__":
    app.run(debug=True)
