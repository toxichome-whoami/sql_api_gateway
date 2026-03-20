import os
import re
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import Engine
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# =========================================================
# Configuration
# =========================================================

API_KEY = os.getenv("API_KEY", "").strip()
ALLOWED_IPS_RAW = os.getenv("ALLOWED_IPS", "").strip()
ALLOWED_IPS = {ip.strip() for ip in ALLOWED_IPS_RAW.split(",") if ip.strip()}

RATE_LIMIT = os.getenv("RATE_LIMIT", "60 per minute").strip()
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))

LOG_FILE = os.getenv("LOG_FILE", "api_gateway.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# =========================================================
# Logging
# =========================================================

if not app.logger.handlers:
    handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    app.logger.addHandler(handler)
    app.logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# =========================================================
# Rate Limiter
# =========================================================

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[RATE_LIMIT]
)

# =========================================================
# Database Registry
# =========================================================

DATABASES = {}


def build_engine(db_url: str) -> Engine:
    engine_kwargs = {
        "pool_pre_ping": True,
        "future": True,
    }

    if not db_url.startswith("sqlite"):
        engine_kwargs["pool_size"] = DB_POOL_SIZE
        engine_kwargs["max_overflow"] = DB_MAX_OVERFLOW

    return create_engine(db_url, **engine_kwargs)


def load_databases():
    global DATABASES
    DATABASES = {}

    for key, value in os.environ.items():
        if key.startswith("DB_URL_"):
            alias = key[len("DB_URL_"):].strip().lower()
            db_url = value.strip()
            mode = os.getenv(f"DB_MODE_{alias.upper()}", "READWRITE").strip().upper()

            DATABASES[alias] = {
                "url": db_url,
                "mode": mode,
                "engine": build_engine(db_url)
            }

    app.logger.info("Loaded databases: %s", list(DATABASES.keys()))


load_databases()

# =========================================================
# Helpers
# =========================================================

WRITE_KEYWORDS = {
    "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "TRUNCATE",
    "REPLACE", "MERGE", "GRANT", "REVOKE", "VACUUM", "ANALYZE"
}


def get_client_ip():
    x_forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if x_forwarded_for:
        return x_forwarded_for
    return request.remote_addr or "unknown"


def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        provided_key = request.headers.get("X-API-Key", "").strip() or request.args.get("api_key", "").strip()

        if not API_KEY:
            return jsonify({"error": "Server misconfiguration: API_KEY not set"}), 500

        if provided_key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return wrapper


def require_ip_allowlist(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not ALLOWED_IPS:
            return f(*args, **kwargs)

        client_ip = get_client_ip()
        if client_ip not in ALLOWED_IPS:
            return jsonify({"error": "Forbidden: IP not allowed", "ip": client_ip}), 403

        return f(*args, **kwargs)
    return wrapper


def get_db_or_404(db_name: str):
    db = DATABASES.get(db_name.lower())
    if not db:
        return None, (jsonify({"error": f"Unknown database '{db_name}'"}), 404)
    return db, None


def is_select_query(sql: str) -> bool:
    return bool(re.match(r"^\s*SELECT\b", sql, flags=re.IGNORECASE))


def has_limit_clause(sql: str) -> bool:
    return bool(re.search(r"\bLIMIT\s+\d+\b", sql, flags=re.IGNORECASE))


def normalize_sql(sql: str) -> str:
    return sql.strip().rstrip(";").strip()


def enforce_select_limit(sql: str) -> str:
    normalized = normalize_sql(sql)
    if is_select_query(normalized) and not has_limit_clause(normalized):
        return f"{normalized} LIMIT 1000"
    return normalized


def first_sql_keyword(sql: str) -> str:
    normalized = normalize_sql(sql)
    match = re.match(r"^\s*([A-Z]+)\b", normalized, flags=re.IGNORECASE)
    return match.group(1).upper() if match else ""


def is_write_query(sql: str) -> bool:
    keyword = first_sql_keyword(sql)
    return keyword in WRITE_KEYWORDS


def validate_readonly(db_mode: str, sql: str):
    if db_mode == "READONLY" and is_write_query(sql):
        raise PermissionError("Write operation blocked: database is in READONLY mode")


def rows_to_dicts(result):
    if result.returns_rows:
        return [dict(row._mapping) for row in result.fetchall()]
    return None


def log_request_and_sql(path, method, db_name=None, sql=None, elapsed_ms=None, error=None):
    payload = {
        "ip": get_client_ip(),
        "method": method,
        "path": path,
        "db": db_name,
        "elapsed_ms": elapsed_ms,
        "sql": sql,
        "error": str(error) if error else None
    }
    app.logger.info(json.dumps(payload, default=str))


def get_tables(db_name: str):
    db = DATABASES[db_name.lower()]
    inspector = inspect(db["engine"])
    return inspector.get_table_names()


def get_schema(db_name: str, table_name: str):
    db = DATABASES[db_name.lower()]
    inspector = inspect(db["engine"])
    columns = inspector.get_columns(table_name)
    pk = inspector.get_pk_constraint(table_name)

    primary_keys = set(pk.get("constrained_columns") or [])

    schema = []
    for col in columns:
        schema.append({
            "name": col.get("name"),
            "type": str(col.get("type")),
            "nullable": col.get("nullable"),
            "default": str(col.get("default")) if col.get("default") is not None else None,
            "primary_key": col.get("name") in primary_keys
        })

    return schema

# =========================================================
# Request Hooks
# =========================================================

@app.before_request
def before_request():
    request._start_time = time.perf_counter()


@app.after_request
def after_request(response):
    elapsed_ms = round((time.perf_counter() - getattr(request, "_start_time", time.perf_counter())) * 1000, 2)
    try:
        log_request_and_sql(
            path=request.path,
            method=request.method,
            elapsed_ms=elapsed_ms
        )
    except Exception:
        pass
    return response

# =========================================================
# Error Handlers
# =========================================================

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded"}), 429


@app.errorhandler(404)
def not_found_handler(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error_handler(e):
    return jsonify({"error": "Internal server error"}), 500

# =========================================================
# Routes
# =========================================================

@app.route("/health", methods=["GET"])
def health():
    results = {}

    for alias, db in DATABASES.items():
        try:
            with db["engine"].connect() as conn:
                conn.execute(text("SELECT 1"))
            results[alias] = {
                "status": "online",
                "mode": db["mode"]
            }
        except Exception as e:
            results[alias] = {
                "status": "offline",
                "mode": db["mode"],
                "error": str(e)
            }

    return jsonify({
        "status": "ok",
        "databases": results
    })


@app.route("/api/databases", methods=["GET"])
@require_ip_allowlist
@require_api_key
def list_databases():
    return jsonify({
        "databases": [
            {"name": alias, "mode": cfg["mode"]}
            for alias, cfg in DATABASES.items()
        ]
    })


@app.route("/api/<db_name>/tables", methods=["GET"])
@require_ip_allowlist
@require_api_key
def list_tables(db_name):
    db, err = get_db_or_404(db_name)
    if err:
        return err

    try:
        tables = get_tables(db_name)
        return jsonify({
            "database": db_name.lower(),
            "tables": tables
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/<db_name>/table/<table_name>/schema", methods=["GET"])
@require_ip_allowlist
@require_api_key
def get_table_schema(db_name, table_name):
    db, err = get_db_or_404(db_name)
    if err:
        return err

    try:
        schema = get_schema(db_name, table_name)
        return jsonify({
            "database": db_name.lower(),
            "table": table_name,
            "schema": schema
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/<db_name>/query", methods=["POST"])
@require_ip_allowlist
@require_api_key
def execute_query(db_name):
    db, err = get_db_or_404(db_name)
    if err:
        return err

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    single_query = payload.get("query")
    single_params = payload.get("params", {})
    batch_queries = payload.get("queries")

    if not single_query and not batch_queries:
        return jsonify({"error": "Provide either 'query' or 'queries'"}), 400

    start = time.perf_counter()

    try:
        if single_query:
            sql = enforce_select_limit(single_query)
            validate_readonly(db["mode"], sql)

            with db["engine"].begin() as conn:
                result = conn.execute(text(sql), single_params or {})
                rows = rows_to_dicts(result)

                response = {
                    "database": db_name.lower(),
                    "mode": db["mode"],
                    "query": sql,
                    "rowcount": result.rowcount
                }

                if rows is not None:
                    response["rows"] = rows

            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            log_request_and_sql(
                path=request.path,
                method=request.method,
                db_name=db_name.lower(),
                sql=sql,
                elapsed_ms=elapsed_ms
            )
            return jsonify(response)

        if batch_queries:
            if not isinstance(batch_queries, list) or not batch_queries:
                return jsonify({"error": "'queries' must be a non-empty list"}), 400

            responses = []

            with db["engine"].begin() as conn:
                for idx, item in enumerate(batch_queries, start=1):
                    if not isinstance(item, dict) or "query" not in item:
                        return jsonify({"error": f"Invalid query object at index {idx - 1}"}), 400

                    sql = enforce_select_limit(item["query"])
                    params = item.get("params", {}) or {}

                    validate_readonly(db["mode"], sql)

                    result = conn.execute(text(sql), params)
                    rows = rows_to_dicts(result)

                    entry = {
                        "index": idx,
                        "query": sql,
                        "rowcount": result.rowcount
                    }
                    if rows is not None:
                        entry["rows"] = rows

                    responses.append(entry)

            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            log_request_and_sql(
                path=request.path,
                method=request.method,
                db_name=db_name.lower(),
                sql=f"BATCH ({len(batch_queries)} queries)",
                elapsed_ms=elapsed_ms
            )

            return jsonify({
                "database": db_name.lower(),
                "mode": db["mode"],
                "transaction": "committed",
                "results": responses
            })

    except PermissionError as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        log_request_and_sql(
            path=request.path,
            method=request.method,
            db_name=db_name.lower(),
            sql=single_query or "BATCH",
            elapsed_ms=elapsed_ms,
            error=e
        )
        return jsonify({"error": str(e)}), 403

    except SQLAlchemyError as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        log_request_and_sql(
            path=request.path,
            method=request.method,
            db_name=db_name.lower(),
            sql=single_query or "BATCH",
            elapsed_ms=elapsed_ms,
            error=e
        )
        return jsonify({
            "error": "Database error",
            "details": str(e)
        }), 400

    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        log_request_and_sql(
            path=request.path,
            method=request.method,
            db_name=db_name.lower(),
            sql=single_query or "BATCH",
            elapsed_ms=elapsed_ms,
            error=e
        )
        return jsonify({
            "error": "Unexpected server error",
            "details": str(e)
        }), 500

# =========================================================
# Main
# =========================================================

if __name__ == "__main__":
    app.run(debug=False)