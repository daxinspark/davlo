# Fabric notebook source

# METADATA ********************

# META {
# META   "kernel_info": {
# META     "name": "jupyter",
# META     "jupyter_kernel_name": "python3.11"
# META   },
# META   "dependencies": {}
# META }

# CELL ********************

from azure.identity import ClientSecretCredential
from azure.storage.filedatalake import DataLakeServiceClient
from azure.core.credentials import AccessToken
from azure.core.credentials import TokenCredential
from azure.storage.filedatalake import DataLakeServiceClient

import time
import pandas as pd
import json

import sempy.fabric as fabric


# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

def get_file_system_client(lh_url:str = "https://onelake.dfs.fabric.microsoft.com/086e574d-a26f-4a9d-a34d-af3125924f27/d30e8df9-0551-46b6-805e-cfc054b195be"):
    class SimpleTokenCredential(TokenCredential):
        def __init__(self, token):
            self._token = token
        
        def get_token(self, *scopes, **kwargs):
            # notebookutils token does not provide expiry, so set a short lifetime
            return AccessToken(self._token, int(time.time()) + 3600)

    # Get token for storage
    raw_token = notebookutils.credentials.getToken("https://storage.azure.com/")

    # Wrap in credential
    credential = SimpleTokenCredential(raw_token)

    service_client = DataLakeServiceClient(account_url=lh_url, credential=credential)
    file_system_client = service_client.get_file_system_client('/Files')

    return file_system_client


def get_config_file(file_url: str = "davlo_config.json", log:bool = False) -> dict:
    file_client = get_file_system_client().get_file_client(file_url)
    downloaded_file = file_client.download_file()
    file_content = downloaded_file.readall()
    config_file = (json.loads(file_content))

    if log:
        print(f"Config Name: {config_file['config']}")
        print(f"Version: {config_file['version']}\n")

        print("Modules:")
        for module, details in config_file.get("modules", {}).items():
            print(f"  - {module}: Enabled={details.get('enabled')}")

        workspaces = len(config_file.get("workspaces", 0))
        print(f"\nWorkspaces: {workspaces}\n")
    return config_file

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

def check_single_module(module_name:str, config_file:dict, log:bool = False) -> bool:
    all_modules = config_file.get('modules', None)
    if not all_modules:
        if log:
            print(f"modules not found")
        return False


    single_module = all_modules.get(module_name, None)
    if not single_module:
        if log:
            print(f"modules not found")
        return False
    
    if log:
        print(f"module: '{module_name}' found")

    return single_module.get('isactive', False)

def get_single_workspace(workspace_uri:str, config_file:dict, log:bool = False):
    all_workspaces = config_file.get('workspaces', None)
    if not all_workspaces:
        if log:
            print(f"workspaces not found")
        return False, {}
    
    single_workspace = next((w for w in config_file.get("workspaces", []) if w.get("workspace_uri") == workspace_uri), None)
    
    if not single_workspace:
        if log:
            print(f"workspace {workspace_uri} not found")
        return False, {}
    
    if log:
        print(f"workspace: '{workspace_uri}' found")

    return True, single_workspace

def check_single_workspace_uri(workspace_uri:str, config_file:dict, log:bool = False) -> bool:
    found, single_workspace = get_single_workspace(workspace_uri, config_file, log)
    if not found:
        return False
    return single_workspace.get('isactive', False)

def check_workspace_module(module_name:str, workspace_uri:str, config_file:dict, log:bool = False) -> bool:
    found, single_workspace = get_single_workspace(workspace_uri, config_file, log)
    if not found:
        return False
    
    paid_modules = single_workspace.get('paid_modules', [])
    if paid_modules == []:
        return False
    
    if module_name in paid_modules:
        return True
    else:
        return False

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

def get_sql_secret(config_file: dict):
    from azure.identity import ClientSecretCredential
    from azure.keyvault.secrets import SecretClient

    tenant_id = config_file.get('sp').get('tenant_id')
    client_id = config_file.get('sp').get('client_id')        
    encrypted_bytes = config_file.get('sp').get('client_secret')
    client_secret = (bytes([b ^ 42 for b in encrypted_bytes.encode("latin1")]).decode())

    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )

    kv_uri = config_file.get('keyvault').get('url')

    # Create client
    secret_client = SecretClient(vault_url=kv_uri, credential=credential)
    
    server = secret_client.get_secret(config_file.get('sql').get('server_url')).value
    user = secret_client.get_secret(config_file.get('sql').get('user')).value
    password = secret_client.get_secret(config_file.get('sql').get('password')).value
    database = config_file.get('sql').get('database')

    return server, user, password, database


def connect_to_db(config_file):
    import pyodbc

    server, username, password, database = get_sql_secret(config_file=config_file)

    # ODBC Driver (must be installed on machine, usually "ODBC Driver 18 for SQL Server")
    driver = '{ODBC Driver 18 for SQL Server}'

    connection_string = f'''
        DRIVER={driver};
        SERVER={server};
        DATABASE={database};
        UID={username};
        PWD={password};
        Encrypt=yes;
        TrustServerCertificate=no;
        Connection Timeout=30;
    '''

    conn = pyodbc.connect(connection_string)
    return conn

def get_conn(config_file: dict):
    return connect_to_db(config_file=config_file)


def query_to_pd_config_db(query:str, conn= None) -> pd.DataFrame:

    if not conn:
        config_file = get_config_file(log=False)
        conn = connect_to_db(config_file=config_file)

    # Test query
    df = pd.read_sql(query, conn)   # here conn is your pyodbc connection object

    return df


def run_sql_config_db(query: str, conn=None, ultra_safe: bool = True):
    """
    Execute a SQL query against the config DB with safety controls.
    Returns a dict:
      success: bool
      query: original query
      mode: ultra_safe | read_only | dml
      columns, rows, rowcount (for SELECT)
      rowcount (for DML)
      error (on failure)
    ultra_safe=True permits ONLY a single SELECT (or WITH ... SELECT) statement.
    """
    import re
    import pyodbc

    original_query = query
    if query is None:
        return {"success": False, "error": "No query provided", "query": original_query}

    query = query.strip()
    if not query:
        return {"success": False, "error": "Empty query", "query": original_query}

    # Helpers
    def _single_statement(q: str) -> bool:
        semis = [m.start() for m in re.finditer(r";", q)]
        if not semis:
            return True
        return len(semis) == 1 and semis[0] == len(q) - 1  # only one trailing semicolon

    def _balanced_quotes(q: str) -> bool:
        return q.count("'") % 2 == 0 and q.count('"') % 2 == 0

    def _is_select(q_lower: str) -> bool:
        return q_lower.startswith("select") or q_lower.startswith("with")

    q_lower = query.lower()

    # Ultra safe: only SELECT
    if ultra_safe:
        if not _is_select(q_lower.lstrip()):
            return {"success": False, "error": "Only SELECT queries allowed in ultra_safe mode", "query": original_query}
        if not _single_statement(query):
            return {"success": False, "error": "Multiple statements not allowed", "query": original_query}
        if not _balanced_quotes(query):
            return {"success": False, "error": "Unbalanced quotes", "query": original_query}
        forbidden = [
            r"\binsert\b", r"\bupdate\b", r"\bdelete\b", r"\bmerge\b",
            r"\bdrop\b", r"\balter\b", r"\btruncate\b", r"\bexec\b",
            r"\bcreate\b", r"\bgrant\b", r"\brevoke\b", r"\battach\b",
            r"\bdetach\b", r"\bbackup\b", r"\brestore\b"
        ]
        if any(re.search(pat, q_lower) for pat in forbidden):
            return {"success": False, "error": "Only pure SELECT allowed", "query": original_query}
        is_select = True
        mode = "ultra_safe"
    else:
        # Broader but still restricted
        if not _single_statement(query):
            return {"success": False, "error": "Multiple statements not allowed", "query": original_query}
        if not _balanced_quotes(query):
            return {"success": False, "error": "Unbalanced quotes", "query": original_query}

        forbidden = [
            r"\bdrop\b", r"\balter\b", r"\btruncate\b", r"\bexec\b",
            r"\bxp_", r"\bsp_", r"\battach\b", r"\bdetach\b",
            r"\bbackup\b", r"\brestore\b", r"\bcreate\s+login\b",
            r"\bcreate\s+user\b", r"\bgrant\b", r"\brevoke\b"
        ]
        if any(re.search(pat, q_lower) for pat in forbidden):
            return {"success": False, "error": "Forbidden keyword detected", "query": original_query}

        # Basic incomplete DML detection
        tokens = q_lower.replace(";", "").split()
        first = tokens[0] if tokens else ""
        if first == "insert":
            # Require pattern: INSERT INTO <table> ...
            if not re.match(r"^\s*insert\s+into\s+\S+", q_lower):
                return {"success": False, "error": "Query rejected: Incomplete or malformed INSERT statement", "query": original_query}
        elif first in ("update", "delete", "merge"):
            if len(tokens) < 2:
                return {"success": False, "error": f"Query rejected: Incomplete {first.upper()} statement", "query": original_query}

        is_select = _is_select(q_lower)
        mode = "read_only" if is_select else "dml"

    created_conn = False
    try:
        if conn is None:
            config_file = get_config_file(log=False)
            conn = connect_to_db(config_file=config_file)
            created_conn = True

        cursor = conn.cursor()
        cursor.execute(query)

        if is_select:
            columns = [c[0] for c in (cursor.description or [])]
            rows = cursor.fetchall()
            return {
                "success": True,
                "query": original_query,
                "mode": mode,
                "columns": columns,
                "rows": [tuple(r) for r in rows],
                "rowcount": len(rows)
            }
        else:
            # DML path
            conn.commit()
            return {
                "success": True,
                "query": original_query,
                "mode": mode,
                "rowcount": cursor.rowcount
            }

    except pyodbc.Error as e:
        # Rollback only for DML
        try:
            if conn and not is_select:
                conn.rollback()
        except Exception:
            pass
        return {
            "success": False,
            "query": original_query,
            "mode": mode if 'mode' in locals() else "unknown",
            "error": f"Database error: {e}"
        }
    except Exception as e:
        return {
            "success": False,
            "query": original_query,
            "mode": mode if 'mode' in locals() else "unknown",
            "error": str(e)
        }
    finally:
        if created_conn and conn:
            try:
                conn.close()
            except Exception:
                pass


# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

class DavloConfig:
    """
    Convenience wrapper for config DB operations.
    Holds:
      config_file: dict with Azure + SQL settings
      conn: live pyodbc connection (lazy)
      workspace_id: optional workspace / tenant scope
    """
    def __init__(self):
        self.config_file = get_config_file(log=False)
        self.workspace_id = fabric.get_notebook_workspace_id()
        self.conn = connect_to_db(self.config_file)

    def ensure_connection(self):
        if self.conn is None:
            self.conn = connect_to_db(self.config_file)
        return self.conn

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            finally:
                self.conn = None

    def run_query(self, query: str, ultra_safe: bool = True):
        self.ensure_connection()
        return run_sql_config_db(query=query, conn=self.conn, ultra_safe=ultra_safe)

    def insert_logging_row(self):

        sql = f"""
        INSERT INTO
        VALUES (?, ?, ?, ?, ?, SYSUTCDATETIME())
        """

        response = run_sql_config_db(query=sql, conn=self.conn,ultra_safe=False)
        print(response)
    
    def get_logging_row(self):

        sql = f"""
        SELECT TOP(10) * FROM LOGGING.ActivityLog
        """

        response = run_sql_config_db(query=sql, conn=self.conn,ultra_safe=False)
        return response


# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

dav = DavloConfig()

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

dav.get_logging_row().get('rows')

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

run_sql_config_db(query="PUT", ultra_safe=False)

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

config_file = get_config_file(log=True)

conn = get_conn(config_file=config_file)
query_config_db(query = "SELECT TOP 5 name FROM sys.databases", conn=conn)

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

def davlo_eligible(module_name: str, log:bool = False):
    # Get DavLo config file 
    config_file = get_config_file(log=log)

    # Check if workspace exists
    workspace_id = fabric.get_notebook_workspace_id()
    if not check_single_workspace_uri(workspace_uri=workspace_id, config_file=config_file, log=log):
        return False


    # Check if module exists
    if not check_single_module(module_name = module_name,config_file=config_file, log=log):
        return False
    
    # Check if workspace is eligible for module
    return check_workspace_module(module_name = module_name,workspace_uri=workspace_id,config_file=config_file, log=log)

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }
