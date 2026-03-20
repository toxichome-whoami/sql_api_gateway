import os
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Header, status
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup FastAPI App
app = FastAPI(
    title="Universal Secure API Gateway",
    description="Secure dynamic multi-database gateway to run queries programmatically.",
    version="1.0.0"
)

# ----------------- Configuration & Security -----------------
API_KEY = os.environ.get("API_KEY", "your_super_secret_api_key_here")

def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    """Dependency to check the API Key from headers for maximum security."""
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    return x_api_key

# ----------------- Dynamic Database Connection Pool -----------------
# We store SQLAlchemy engines here to reuse connections.
# This ensures it's extremely fast and uses low resources.
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Database '{db_name}' not configured in environment (Missing '{env_var_name}')."
        )

    try:
        # Create a new engine, enable ping to checking connection health.
        engine = create_engine(connection_string, pool_pre_ping=True)
        db_engines[db_name_upper] = engine
        return engine
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize database engine for '{db_name}': {str(e)}"
        )

# ----------------- API Models -----------------
class QueryRequest(BaseModel):
    query: str
    params: dict = {}

# ----------------- Endpoints -----------------
@app.get("/")
def read_root():
    return {"status": "Gateway is running securely. Access restricted."}

@app.get("/api/databases", dependencies=[Depends(verify_api_key)])
def list_databases():
    """List all configured database endpoints dynamically."""
    configured_dbs = []
    for key in os.environ:
        if key.startswith("DB_URL_"):
            configured_dbs.append(key.replace("DB_URL_", "").lower())
    return {"configured_databases": configured_dbs}

@app.post("/api/{db_name}/query", dependencies=[Depends(verify_api_key)])
def execute_database_query(db_name: str, payload: QueryRequest):
    """
    Execute any raw SQL query on the target database dynamically.
    The `{db_name}` MUST match the .env key `DB_URL_{DB_NAME}`.
    WARNING: Sending unstructured user input to this endpoint bypasses API security.
    Make sure your FastApi calls format the SQL safely or you use `params`.
    """
    engine = get_engine(db_name)
    
    try:
        with engine.connect() as connection:
            # text() makes sure sqlalchemy properly wraps the code securely against basic malformat
            sql = text(payload.query)
            result = connection.execute(sql, payload.params)
            
            # Commit if the query modifies data
            if payload.query.strip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER")):
                connection.commit()
                return {
                    "success": True, 
                    "rowcount": result.rowcount,
                    "message": "Query executed and changes committed."
                }
            
            # Else fetch data (e.g. SELECT, SHOW)
            # Convert SQLAlchemy result rows to dictionaries mapping columns to values
            if result.returns_rows:
                columns = result.keys()
                rows = [dict(zip(columns, row)) for row in result.fetchall()]
                return {
                    "success": True,
                    "rowcount": len(rows),
                    "data": rows
                }
            else:
                 return {
                    "success": True, 
                    "message": "Query executed successfully. No rows returned."
                }

    except SQLAlchemyError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Database execution error: {str(err)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal Error: {str(e)}"
        )

# ----------------- App Runner -----------------
if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=True)
