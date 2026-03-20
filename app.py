from sqlalchemy.sql.roles import TruncatedLabelRole
import os
import logging
from flask import Flask, request, jsonify, abort
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv

# --- Initialization ---
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
# Logging is kept to help with cPanel troubleshooting
logging.basicConfig(
    filename=os.path.join(PROJECT_ROOT, 'api_gateway.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

app = Flask(__name__)
API_KEY = os.environ.get("API_KEY")

# --- Security ---
def verify_api_key():
    """Verify API Key from X-API-Key header or api_key query parameter."""
    token = request.headers.get("X-API-Key") or request.args.get("api_key")
    if token != API_KEY:
        logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        abort(401, description="Invalid or missing API Key")

@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler for all exceptions."""
    logger.exception(f"Error: {str(e)}")
    status_code = getattr(e, 'code', 500)
    description = getattr(e, 'description', "Internal Server Error")
    return jsonify({"error": description, "message": str(e)}), status_code

# --- Database Management ---
db_engines = {}

def get_engine(db_name: str):
    """Get or create a cached database engine from environment variables."""
    db_name = db_name.upper()
    if db_name in db_engines:
        return db_engines[db_name]

    connection_string = os.environ.get(f"DB_URL_{db_name}")
    if not connection_string:
        abort(404, description=f"Database '{db_name}' not configured.")

    try:
        engine = create_engine(connection_string, pool_pre_ping=True)
        db_engines[db_name] = engine
        return engine
    except Exception as e:
        abort(500, description=f"Database initialization failed: {str(e)}")

# --- API Endpoints ---

@app.route("/")
def index():
    return jsonify({"status": "Gateway online", "security": "Active"})

@app.route("/api/databases", methods=["GET"])
def list_databases():
    """List all configured databases from environment variables."""
    verify_api_key()
    dbs = [k.replace("DB_URL_", "").lower() for k in os.environ if k.startswith("DB_URL_")]
    return jsonify({"configured_databases": dbs})

@app.route("/api/<db_name>/query", methods=["POST"])
def execute_query(db_name):
    """Execute raw SQL queries with parameter binding support."""
    verify_api_key()

    data = request.get_json()
    if not data or 'query' not in data:
        abort(400, description="Payload must contain 'query'.")

    query_str = data.get('query')
    params = data.get('params', {})

    engine = get_engine(db_name)

    try:
        with engine.connect() as conn:
            sql = text(query_str)
            result = conn.execute(sql, params)

            # Auto-commit for modification queries
            if query_str.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")):
                conn.commit()
                return jsonify({"success": True, "rowcount": result.rowcount})

            # Fetch results for SELECT/SHOW queries
            if result.returns_rows:
                rows = [dict(row._mapping) for row in result.fetchall()]
                return jsonify({"success": True, "rowcount": len(rows), "data": rows})

            return jsonify({"success": True, "message": "Query executed."})

    except SQLAlchemyError as err:
        return jsonify({"error": "Database Error", "message": str(err)}), 400

if __name__ == "__main__":
    app.run(debug=True)
