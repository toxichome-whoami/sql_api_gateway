import os
import re
import time
import json
import logging
import sqlite3
import random
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from functools import wraps

from flask import Flask, request, jsonify, Response, stream_with_context
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine import Engine
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
# Anti-Payload Bombing: Instantly drop requests with body > 5MB
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# =========================================================
# Configuration
# =========================================================

API_KEYS = {}
ALLOWED_IPS_RAW = os.getenv("ALLOWED_IPS", "").strip()
ALLOWED_IPS = {ip.strip() for ip in ALLOWED_IPS_RAW.split(",") if ip.strip()}

RATE_LIMIT = os.getenv("RATE_LIMIT", "120 per minute").strip()
PENALTY_TIMEOUT_SECONDS = int(os.getenv("PENALTY_TIMEOUT_SECONDS", "900"))
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
STREAM_CHUNK_SIZE = int(os.getenv("STREAM_CHUNK_SIZE", "500"))
QUERY_TIMEOUT_SECONDS = int(os.getenv("QUERY_TIMEOUT_SECONDS", "15"))

LOG_FILE = os.getenv("LOG_FILE", "api_gateway.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

LIMITER_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rate_limits.db")

def init_rate_limiter():
    with sqlite3.connect(LIMITER_DB_PATH) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS rate_limits (ip TEXT PRIMARY KEY, window_time TEXT, hits INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, unban_time TEXT)")
        conn.commit()

init_rate_limiter()

# =========================================================
# Logging
# =========================================================

# Always attach the file handler (Flask pre-adds a default StreamHandler,
# so "if not app.logger.handlers" would skip this block entirely).
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(log_formatter)
file_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
app.logger.addHandler(file_handler)
app.logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Log startup configuration
app.logger.info("=== API GATEWAY STARTING ===")
app.logger.info("Log Level: %s | Log File: %s", LOG_LEVEL, LOG_FILE)
app.logger.info("Rate Limit: %s | Pool Size: %d | Max Overflow: %d", RATE_LIMIT, DB_POOL_SIZE, DB_MAX_OVERFLOW)
app.logger.info("IP Allowlist: %s", list(ALLOWED_IPS) if ALLOWED_IPS else "DISABLED (all IPs allowed)")
# API Keys are loaded dynamically in load_api_keys()

# =========================================================
# Request Hooks & Security Shield
# =========================================================

BANNED_IP_CACHE = {}  # Memory Shield for zero-IO blocking

@app.before_request
def enforce_rate_limit():
    client_ip = get_client_ip()
    now_utc = datetime.utcnow()
    current_utc_str = now_utc.strftime('%Y-%m-%d %H:%M:%S')
    current_window_str = now_utc.strftime('%Y-%m-%d %H:%M:00')

    # 1. RAM Shield Check (Sub-millisecond rejection for known attackers)
    if client_ip in BANNED_IP_CACHE:
        unban_dt = BANNED_IP_CACHE[client_ip]
        if now_utc < unban_dt:
            wait_time = int((unban_dt - now_utc).total_seconds())
            return jsonify({"error": f"IP Banned. Too many requests. Try again in {max(0, wait_time)} seconds. (Unban at {unban_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC)"}), 429
        else:
            del BANNED_IP_CACHE[client_ip]

    # 2. SQLite Registry Sync
    try:
        with sqlite3.connect(LIMITER_DB_PATH, timeout=5) as conn:
            cursor = conn.cursor()
            
            # Check for Persistent Ban
            cursor.execute("SELECT unban_time FROM banned_ips WHERE ip = ?", (client_ip,))
            row = cursor.fetchone()
            if row:
                unban_dt = datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S')
                if now_utc < unban_dt:
                    BANNED_IP_CACHE[client_ip] = unban_dt # Lift to RAM shield
                    wait_time = int((unban_dt - now_utc).total_seconds())
                    return jsonify({"error": f"IP Banned. Too many requests. Try again in {max(0, wait_time)} seconds. (Unban at {row[0]} UTC)"}), 429
                else:
                    cursor.execute("DELETE FROM banned_ips WHERE ip = ?", (client_ip,))

            # Hit Tracking
            cursor.execute("SELECT window_time, hits FROM rate_limits WHERE ip = ?", (client_ip,))
            hit_row = cursor.fetchone()
            
            try:
                rate_limit_max = int(RATE_LIMIT.split()[0])
            except:
                rate_limit_max = 120

            if not hit_row:
                cursor.execute("INSERT OR IGNORE INTO rate_limits (ip, window_time, hits) VALUES (?, ?, 1)", (client_ip, current_window_str))
                count = 1
            elif hit_row[0] != current_window_str:
                cursor.execute("UPDATE rate_limits SET window_time = ?, hits = 1 WHERE ip = ?", (current_window_str, client_ip))
                count = 1
            else:
                count = hit_row[1] + 1
                cursor.execute("UPDATE rate_limits SET hits = ? WHERE ip = ?", (count, client_ip))
                
                if count > rate_limit_max:
                    unban_dt = now_utc + timedelta(seconds=PENALTY_TIMEOUT_SECONDS)
                    unban_utc_str = unban_dt.strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute("INSERT OR REPLACE INTO banned_ips (ip, unban_time) VALUES (?, ?)", (client_ip, unban_utc_str))
                    BANNED_IP_CACHE[client_ip] = unban_dt # Immediate RAM shield
                    conn.commit()
                    return jsonify({"error": f"Rate limit exceeded. Banned for {PENALTY_TIMEOUT_SECONDS} seconds. (Unban at {unban_utc_str} UTC)"}), 429

            # 3. Probabilistic Disk Cleanup (Prevents I/O blocking)
            if random.random() < 0.01:
                cursor.execute("DELETE FROM banned_ips WHERE unban_time < ?", (current_utc_str,))
                cursor.execute("DELETE FROM rate_limits WHERE window_time < ?", ((now_utc - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:00'),))
            
            conn.commit()
    except Exception as e:
        app.logger.error("[LIMITER] SQLite Error: %s", str(e))
        # Fail open for rate limiting if DB is locked to maintain availability, or could fail closed for security.

@app.before_request
def start_timer():
    request._start_time = time.perf_counter()

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

    engine = create_engine(db_url, **engine_kwargs)
    return engine.execution_options(timeout=QUERY_TIMEOUT_SECONDS)


def load_databases():
    global DATABASES
    DATABASES = {}

    for key, value in os.environ.items():
        if key.startswith("DB_URL_"):
            alias = key[len("DB_URL_"):].strip().lower()
            db_url = value.strip()
            mode = os.getenv(f"DB_MODE_{alias.upper()}", "READWRITE").strip().upper()

            try:
                engine = build_engine(db_url)
                DATABASES[alias] = {
                    "url": db_url,
                    "mode": mode,
                    "engine": engine
                }
                app.logger.info("[DB REGISTRY] Loaded '%s' | Mode: %s", alias, mode)
            except Exception as e:
                app.logger.error("[DB REGISTRY] FAILED to load '%s': %s", alias, str(e))

    if DATABASES:
        app.logger.info("[DB REGISTRY] Total databases loaded: %d -> %s", len(DATABASES), list(DATABASES.keys()))
    else:
        app.logger.warning("[DB REGISTRY] No databases found. Check DB_URL_* variables in .env.")


def load_api_keys():
    global API_KEYS
    API_KEYS = {}
    for key, value in os.environ.items():
        if key.startswith("API_KEY_"):
            parts = key.split("_")
            if len(parts) >= 4:
                # Format: API_KEY_NAME_ROLE
                name = parts[2]
                role = "_".join(parts[3:]).upper()
                secret = value.strip()
                if secret:
                    API_KEYS[secret] = {"name": name, "role": role}
                    app.logger.info("[AUTH REGISTRY] Loaded key for '%s' | Role: %s", name, role)
                
    if API_KEYS:
        app.logger.info("[AUTH REGISTRY] Total API keys loaded: %d", len(API_KEYS))
    else:
        app.logger.warning("[AUTH REGISTRY] No API keys found! Server will reject all requests.")


load_databases()
load_api_keys()

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

        if not API_KEYS:
            app.logger.error("[AUTH] REJECTED %s %s - No API keys configured on server", request.method, request.path)
            return jsonify({"error": "Server misconfiguration: No API keys configured"}), 500

        auth_context = API_KEYS.get(provided_key)
        if not auth_context:
            app.logger.warning("[AUTH] REJECTED %s %s from %s - Invalid API key", request.method, request.path, get_client_ip())
            return jsonify({"error": "Unauthorized"}), 401

        request.auth_context = auth_context
        app.logger.debug("[AUTH] ACCEPTED %s %s from %s (User: %s)", request.method, request.path, get_client_ip(), auth_context["name"])
        return f(*args, **kwargs)
    return wrapper


def require_ip_allowlist(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not ALLOWED_IPS:
            return f(*args, **kwargs)

        client_ip = get_client_ip()
        if client_ip not in ALLOWED_IPS:
            app.logger.warning("[IP BLOCK] REJECTED %s %s from %s - IP not in allowlist", request.method, request.path, client_ip)
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


def validate_role_for_sql(db_mode: str, role: str, sql: str):
    if db_mode == "READONLY" and is_write_query(sql):
        raise PermissionError("Write operation blocked: database is in READONLY mode")
        
    if role == "READ_ONLY" and is_write_query(sql):
        raise PermissionError(f"Write operation blocked: API key role is {role}")
        
    if role == "WRITE_ONLY" and is_select_query(sql):
        raise PermissionError(f"Read operation blocked: API key role is {role}")


def rows_to_dicts(result):
    if result.returns_rows:
        return [dict(row._mapping) for row in result.fetchall()]
    return None


def log_request_and_sql(path, method, db_name=None, sql=None, elapsed_ms=None, error=None, status_code=None):
    auth_context = getattr(request, "auth_context", {})
    payload = {
        "ip": get_client_ip(),
        "client": auth_context.get("name"),
        "role": auth_context.get("role"),
        "method": method,
        "path": path,
        "db": db_name,
        "elapsed_ms": elapsed_ms,
        "sql": sql,
        "status_code": status_code,
        "error": str(error) if error else None
    }
    if error:
        app.logger.error("[QUERY] %s", json.dumps(payload, default=str))
    else:
        app.logger.info("[QUERY] %s", json.dumps(payload, default=str))


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
    # Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    elapsed_ms = round((time.perf_counter() - getattr(request, "_start_time", time.perf_counter())) * 1000, 2)
    # Log every request with its final status code
    app.logger.info(
        "[REQUEST] %s %s -> %d | %sms | IP: %s",
        request.method,
        request.path,
        response.status_code,
        elapsed_ms,
        get_client_ip()
    )
    return response

# =========================================================
# Error Handlers
# =========================================================

# Manually handled in enforce_rate_limit before_request hook


@app.errorhandler(404)
def not_found_handler(e):
    app.logger.info("[404] %s %s from %s", request.method, request.path, get_client_ip())
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error_handler(e):
    app.logger.error("[500] %s %s from %s - %s", request.method, request.path, get_client_ip(), str(e))
    return jsonify({"error": "Internal server error"}), 500

# =========================================================
# Routes
# =========================================================

@app.route("/health", methods=["GET"])
def health():
    app.logger.info("[HEALTH] Health check initiated from %s", get_client_ip())
    results = {}

    for alias, db in DATABASES.items():
        try:
            with db["engine"].connect() as conn:
                conn.execute(text("SELECT 1"))
            results[alias] = {
                "status": "online",
                "mode": db["mode"]
            }
            app.logger.info("[HEALTH] DB '%s' -> ONLINE", alias)
        except Exception as e:
            results[alias] = {
                "status": "offline",
                "mode": db["mode"],
                "error": str(e)
            }
            app.logger.error("[HEALTH] DB '%s' -> OFFLINE: %s", alias, str(e))

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
        app.logger.warning("[TABLES] DB '%s' not found - requested by %s", db_name, get_client_ip())
        return err

    try:
        tables = get_tables(db_name)
        app.logger.info("[TABLES] Listed %d tables from '%s' for %s", len(tables), db_name, get_client_ip())
        return jsonify({
            "database": db_name.lower(),
            "tables": tables
        })
    except Exception as e:
        app.logger.error("[TABLES] Error listing tables from '%s': %s", db_name, str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/<db_name>/table/<table_name>/schema", methods=["GET"])
@require_ip_allowlist
@require_api_key
def get_table_schema(db_name, table_name):
    db, err = get_db_or_404(db_name)
    if err:
        app.logger.warning("[SCHEMA] DB '%s' not found - requested by %s", db_name, get_client_ip())
        return err

    try:
        schema = get_schema(db_name, table_name)
        app.logger.info("[SCHEMA] Inspected '%s.%s' (%d columns) for %s", db_name, table_name, len(schema), get_client_ip())
        return jsonify({
            "database": db_name.lower(),
            "table": table_name,
            "schema": schema
        })
    except Exception as e:
        app.logger.error("[SCHEMA] Error inspecting '%s.%s': %s", db_name, table_name, str(e))
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
            role = getattr(request, "auth_context", {}).get("role", "")
            validate_role_for_sql(db["mode"], role, sql)
            app.logger.info("[QUERY] Executing single query on '%s' | Type: %s | IP: %s | Role: %s", db_name, first_sql_keyword(sql), get_client_ip(), role)

            if is_select_query(sql):
                def generate_stream():
                    yield '{"database": "' + db_name.lower() + '", "mode": "' + db["mode"] + '", "query": ' + json.dumps(sql) + ', "rows": ['
                    try:
                        with db["engine"].begin() as conn:
                            # Use yield_per to force server-side cursors in the DB driver (max speed, zero RAM buffer)
                            result = conn.execution_options(yield_per=STREAM_CHUNK_SIZE).execute(text(sql), single_params or {})
                            first = True
                            while True:
                                chunk = result.fetchmany(STREAM_CHUNK_SIZE)
                                if not chunk:
                                    break
                                for row in chunk:
                                    if not first:
                                        yield ','
                                    yield json.dumps(dict(row._mapping), default=str)
                                    first = False
                            
                        yield '], "status": "success"}'
                    except Exception as e:
                        app.logger.error("[STREAM ERROR] on '%s' | %s", db_name, str(e))
                        yield '], "error": ' + json.dumps(str(e)) + '}'

                    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                    log_request_and_sql(
                        path=request.path,
                        method=request.method,
                        db_name=db_name.lower(),
                        sql=sql + " (STREAMED)",
                        elapsed_ms=elapsed_ms,
                        status_code=200
                    )

                return Response(stream_with_context(generate_stream()), mimetype="application/json")

            # For non-SELECT single queries
            with db["engine"].begin() as conn:
                result = conn.execute(text(sql), single_params or {})
                response = {
                    "database": db_name.lower(),
                    "mode": db["mode"],
                    "query": sql,
                    "rowcount": result.rowcount
                }

            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            log_request_and_sql(
                path=request.path,
                method=request.method,
                db_name=db_name.lower(),
                sql=sql,
                elapsed_ms=elapsed_ms,
                status_code=200
            )
            return jsonify(response)

        if batch_queries:
            if not isinstance(batch_queries, list) or not batch_queries:
                return jsonify({"error": "'queries' must be a non-empty list"}), 400

            app.logger.info("[BATCH] Starting batch of %d queries on '%s' | IP: %s", len(batch_queries), db_name, get_client_ip())
            responses = []

            with db["engine"].begin() as conn:
                for idx, item in enumerate(batch_queries, start=1):
                    if not isinstance(item, dict) or "query" not in item:
                        app.logger.warning("[BATCH] Invalid query object at index %d", idx - 1)
                        return jsonify({"error": f"Invalid query object at index {idx - 1}"}), 400

                    sql = enforce_select_limit(item["query"])
                    params = item.get("params", {}) or {}

                    role = getattr(request, "auth_context", {}).get("role", "")
                    validate_role_for_sql(db["mode"], role, sql)

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
            app.logger.info("[BATCH] Committed %d queries on '%s' in %sms", len(batch_queries), db_name, elapsed_ms)
            log_request_and_sql(
                path=request.path,
                method=request.method,
                db_name=db_name.lower(),
                sql=f"BATCH ({len(batch_queries)} queries)",
                elapsed_ms=elapsed_ms,
                status_code=200
            )

            return jsonify({
                "database": db_name.lower(),
                "mode": db["mode"],
                "transaction": "committed",
                "results": responses
            })

    except PermissionError as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        app.logger.warning("[PERMISSION] Blocked write on '%s' | %s | IP: %s", db_name, str(e), get_client_ip())
        log_request_and_sql(
            path=request.path,
            method=request.method,
            db_name=db_name.lower(),
            sql=single_query or "BATCH",
            elapsed_ms=elapsed_ms,
            error=e,
            status_code=403
        )
        return jsonify({"error": str(e)}), 403

    except SQLAlchemyError as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        app.logger.error("[DB ERROR] on '%s' | %s | IP: %s", db_name, str(e), get_client_ip())
        log_request_and_sql(
            path=request.path,
            method=request.method,
            db_name=db_name.lower(),
            sql=single_query or "BATCH",
            elapsed_ms=elapsed_ms,
            error=e,
            status_code=400
        )
        return jsonify({
            "error": "Database error",
            "details": str(e)
        }), 400

    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        app.logger.error("[FATAL] Unexpected error on '%s' | %s | IP: %s", db_name, str(e), get_client_ip())
        log_request_and_sql(
            path=request.path,
            method=request.method,
            db_name=db_name.lower(),
            sql=single_query or "BATCH",
            elapsed_ms=elapsed_ms,
            error=e,
            status_code=500
        )
        return jsonify({
            "error": "Unexpected server error",
            "details": str(e)
        }), 500

# =========================================================
# Main
# =========================================================

if __name__ == "__main__":
    app.logger.info("=== API GATEWAY READY (Manual Start) ===")
    app.run(debug=False)