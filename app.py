from sqlalchemy.sql.roles import TruncatedLabelRole
import os
import logging
from flask import Flask, request, jsonify, abort
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv

# --- Initialization ---
# Get current directory and configure logging
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(
    filename=os.path.join(PROJECT_ROOT, 'api_gateway.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

app = Flask(__name__)
API_KEY = os.environ.get("API_KEY")

# --- Security ---
def verify_api_key():
    """Verify Master Key from X-API-Key header OR api_key query parameter."""
    token = request.headers.get("X-API-Key") or request.args.get("api_key")
    if token != API_KEY:
        logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        abort(401, description="Invalid or missing API Key")

@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler converting all errors to JSON."""
    logger.exception(f"Error: {str(e)}")
    status_code = getattr(e, 'code', 500)
    description = getattr(e, 'description', "Internal Server Error")
    return jsonify({"error": description, "message": str(e)}), status_code

# --- Database Management ---
db_engines = {}

def get_engine(db_name: str):
    """Retrieve or initialize a SQLAlchemy engine for the specified database."""
    db_name = db_name.upper()
    if db_name in db_engines:
        return db_engines[db_name]

    # Look for DB_URL_{NAME} in environment
    connection_string = os.environ.get(f"DB_URL_{db_name}")
    if not connection_string:
        abort(404, description=f"Database '{db_name}' not configured in environment.")

    try:
        # pool_pre_ping ensures we don't use stale connections from the pool
        engine = create_engine(connection_string, pool_pre_ping=True)
        db_engines[db_name] = engine
        return engine
    except Exception as e:
        abort(500, description=f"Database initialization failed: {str(e)}")

# --- Endpoints ---

@app.route("/")
def index():
    return jsonify({"status": "Gateway online", "security": "Active"})

@app.route("/health", methods=["GET"])
def health_check():
    """Monitor connectivity to all configured databases."""
    status = {"status": "ok", "databases": {}}
    for key in os.environ:
        if key.startswith("DB_URL_"):
            name = key.replace("DB_URL_", "").lower()
            try:
                engine = get_engine(name)
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                status["databases"][name] = "connected"
            except:
                status["status"] = "degraded"
                status["databases"][name] = "offline"
    return jsonify(status)

@app.route("/api/databases", methods=["GET"])
def list_databases():
    """List all database aliases available in this gateway."""
    verify_api_key()
    dbs = [k.replace("DB_URL_", "").lower() for k in os.environ if k.startswith("DB_URL_")]
    return jsonify({"configured_databases": dbs})

@app.route("/api/<db_name>/tables", methods=["GET"])
def list_tables(db_name):
    """Discover all table names in a database dynamically."""
    verify_api_key()
    engine = get_engine(db_name)
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    return jsonify({"database": db_name, "tables": tables})

@app.route("/api/<db_name>/table/<table_name>/schema", methods=["GET"])
def get_table_schema(db_name, table_name):
    """Discover column definitions for any table."""
    verify_api_key()
    engine = get_engine(db_name)
    inspector = inspect(engine)
    columns = inspector.get_columns(table_name)
    schema = [{"name": c['name'], "type": str(c['type']), "nullable": c['nullable']} for c in columns]
    return jsonify({"database": db_name, "table": table_name, "schema": schema})

@app.route("/api/<db_name>/query", methods=["POST"])
def execute_query(db_name):
    """Execute raw SQL with support for parameter binding and auto-commit."""
    verify_api_key()
    
    data = request.get_json()
    if not data or 'query' not in data:
        abort(400, description="Missing 'query' in request payload.")
    
    query_str = data.get('query')
    params = data.get('params', {})
    
    engine = get_engine(db_name)
    
    try:
        with engine.connect() as conn:
            sql = text(query_str)
            result = conn.execute(sql, params)
            
            # Detect modifying queries to commit changes
            if query_str.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")):
                conn.commit()
                return jsonify({"success": True, "rowcount": result.rowcount})
            
            # Return rows for SELECT and dynamic metadata queries
            if result.returns_rows:
                rows = [dict(row._mapping) for row in result.fetchall()]
                return jsonify({"success": True, "rowcount": len(rows), "data": rows})
            
            return jsonify({"success": True, "message": "Query executed successfully."})

    except SQLAlchemyError as err:
        return jsonify({"error": "Database Execution Error", "message": str(err)}), 400

if __name__ == "__main__":
    app.run(debug=True)
