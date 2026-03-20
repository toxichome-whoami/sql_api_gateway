import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# ----------------- Configuration & Security -----------------
API_KEY = os.environ.get("API_KEY", "your_super_secret_api_key_here")

def verify_api_key():
    """Check the API Key from headers for maximum security."""
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key != API_KEY:
        abort(401, description="Invalid API Key")

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": error.description}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": error.description}), 404

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": error.description}), 400

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error"}), 500

# ----------------- Dynamic Database Connection Pool -----------------
db_engines = {}

def get_engine(db_name: str):
    """Dynamically get or create a database engine based on the .env db name."""
    db_name_upper = db_name.upper()
    if db_name_upper in db_engines:
        return db_engines[db_name_upper]

    # Look for DB_URL_{DB_NAME} in environment
    env_var_name = f"DB_URL_{db_name_upper}"
    connection_string = os.environ.get(env_var_name)
    
    if not connection_string:
        abort(404, description=f"Database '{db_name}' not configured in environment (Missing '{env_var_name}').")

    try:
        # Create a new engine, enable ping to checking connection health.
        engine = create_engine(connection_string, pool_pre_ping=True)
        db_engines[db_name_upper] = engine
        return engine
    except Exception as e:
        abort(500, description=f"Failed to initialize database engine for '{db_name}': {str(e)}")

# ----------------- Endpoints -----------------

@app.route("/")
def read_root():
    return jsonify({"status": "Gateway is running securely. Access restricted."})

@app.route("/api/databases", methods=["GET"])
def list_databases():
    """List all configured database endpoints dynamically."""
    verify_api_key()
    configured_dbs = []
    for key in os.environ:
        if key.startswith("DB_URL_"):
            configured_dbs.append(key.replace("DB_URL_", "").lower())
    return jsonify({"configured_databases": configured_dbs})

@app.route("/api/<db_name>/query", methods=["POST"])
def execute_database_query(db_name):
    """
    Execute any raw SQL query on the target database dynamically.
    The `<db_name>` MUST match the .env key `DB_URL_{DB_NAME}`.
    """
    verify_api_key()
    
    data = request.get_json()
    if not data or 'query' not in data:
        abort(400, description="Missing 'query' in request body.")
    
    query_str = data.get('query')
    params = data.get('params', {})
    
    engine = get_engine(db_name)
    
    try:
        with engine.connect() as connection:
            # text() makes sure sqlalchemy properly wraps the code securely
            sql = text(query_str)
            result = connection.execute(sql, params)
            
            # Commit if the query modifies data
            if query_str.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")):
                connection.commit()
                return jsonify({
                    "success": True, 
                    "rowcount": result.rowcount,
                    "message": "Query executed and changes committed."
                })
            
            # Else fetch data (e.g. SELECT, SHOW)
            if result.returns_rows:
                columns = result.keys()
                rows = [dict(zip(columns, row)) for row in result.fetchall()]
                return jsonify({
                    "success": True,
                    "rowcount": len(rows),
                    "data": rows
                })
            else:
                 return jsonify({
                    "success": True, 
                    "message": "Query executed successfully. No rows returned."
                })

    except SQLAlchemyError as err:
        return jsonify({"error": f"Database execution error: {str(err)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Internal Error: {str(e)}"}), 500

if __name__ == "__main__":
    # For local development
    app.run(host="0.0.0.0", port=5000)
