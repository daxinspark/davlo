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
from typing import Any, Iterable, Optional, Sequence, Dict
import re

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



# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# MARKDOWN ********************

# ## dav_client
# 
# Lightweight helper for safe SELECT (limited) and INSERT operations.
# 
# ### Get (read)
# 
# ```python
# # First 100 rows (default)
# df = dav_client.get('logging.ActivityLogEncryption')
# 
# # All rows
# df_all = dav_client.get('logging.ActivityLogEncryption', full_load=True)
# 
# # Filter + order (ONLY starts with WHERE / ORDER BY / GROUP BY)
# df_ok = dav_client.get(
#     'logging.ActivityLogEncryption',
#     params="WHERE Success = 1 ORDER BY DateCreated DESC"
# )
# ```
# 
# ### Post (insert)
# 
# ```python
# res_df = dav_client.post(
#     table='logging.ActivityLogEncryption',
#     data={
#         "Process": "Encryption",
#         "DurationMs": 392850,
#         "RowsAffected": 231,
#         "EncryptedColumns": "internalId;BSN",
#         "Success": True,
#         "WorkspaceID": fabric.get_workspace_id()  # if available
#     }
# )
# print(res_df)
# ```
# 
# Returned DataFrame columns:
# - success (bool)
# - error (str | None)
# - rowcount (int | None)
# - used_columns (list | None)
# - ignored_columns (list | None)
# - table (str)
# 
# ## Method Summary
# 
# ```text
# dav_client.get(table, full_load=False, params=None)
#     -> pandas DataFrame of rows (TOP 100 unless full_load=True)
# 
# dav_client.post(table, data: dict)
#     -> single-row pandas DataFrame with success/error metadata
# ```
# 
# ## Safety Notes
# 
# - Table name validated: only alphanumeric + underscore, optional schema.
# - get params fragment must start with WHERE / ORDER BY / GROUP BY and forbids DDL/DML tokens.
# - post uses parameterized INSERT (? placeholders).
# - Unknown keys in data are ignored; if none match, success=False with descriptive error.
# 
# ## Internal Helpers (not typically called directly)
# 
# ```text
# _sanitize_table_name, _split_schema_table, _validate_optional_clause
# DavloError, DavloInsertError
# ```
# 
# ## Troubleshooting
# 
# | Issue | Cause | Fix |
# |-------|-------|-----|
# | success=False, "No valid columns..." | Key names mismatch DB columns | Adjust key names to exact column names |
# | Warning about SQLAlchemy (suppressed) | pandas notice on pyodbc | Already suppressed via warnings.filterwarnings |


# CELL ********************

import warnings

# Suppress pandas warning about non-SQLAlchemy DBAPI connections (pyodbc usage is intentional)
warnings.filterwarnings(
    'ignore',
    category=UserWarning,
    message=r'pandas only supports SQLAlchemy connectable.*'
)


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



class DavloConfig:
    """
    Convenience wrapper for config DB operations.

    Attributes:
      config_file: dict with Azure + SQL settings
      conn: live pyodbc connection (lazy)
      workspace_id: workspace / tenant scope (GUID or string)
    """
    def __init__(self):
        # Lazy-load config file
        self.config_file = get_config_file(log=False)
        # Workspace (best-effort; if not running inside Fabric, falls back to None)
        try:
            import fabric  # type: ignore
            self.workspace_id = fabric.get_notebook_workspace_id()
        except Exception:
            self.workspace_id = None
        self.conn = None  # lazy
        self.ensure_connection()

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

    # ---------------------------- Public API ---------------------------- #
    def get(self, table: str, full_load: bool = False, params: str | None = None):
        """Return rows from table as pandas DataFrame.

        Args:
          table: Target table name (schema.table or table). Will be validated.
          full_load: If True returns all rows, else TOP (100).
          params: Optional trailing SQL fragment that may start with WHERE / ORDER BY / GROUP BY.
                  It's validated to avoid injection (no semicolons, comments, or DDL/DML keywords).
        """
        import pandas as pd
        conn = self.ensure_connection()
        safe_table = _sanitize_table_name(table)
        top_clause = '' if full_load else 'TOP (100) '
        where_order_clause = _validate_optional_clause(params) if params else ''
        sql = f"SELECT {top_clause}* FROM {safe_table} {where_order_clause}".strip()
        # Use pandas read_sql_query; no parameters because user fragment validated & sanitized
        return pd.read_sql_query(sql, conn)

    def post(self, table: str, data: dict):
        """Insert a new row safely using parameterized query and return status as DataFrame.

        Args:
          table: Target table name (schema.table or table). Will be validated.
          data: Dict mapping column -> value. Unknown columns are ignored.

        Returns:
          pandas.DataFrame (single row) with columns:
            success, error, rowcount, used_columns, ignored_columns, table
        """
        import pandas as pd
        result = {
            'success': False,
            'error': None,
            'rowcount': None,
            'used_columns': None,
            'ignored_columns': None,
            'table': table,
        }
        try:
            if not isinstance(data, dict) or not data:
                raise DavloInsertError("data must be a non-empty dict (got type: %s)" % type(data).__name__)
            conn = self.ensure_connection()
            safe_table = _sanitize_table_name(table)
            cursor = conn.cursor()
            schema, pure_table = _split_schema_table(safe_table)
            if schema:
                col_query = """SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?"""
                cursor.execute(col_query, (schema, pure_table))
            else:
                col_query = """SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ?"""
                cursor.execute(col_query, (pure_table,))
            valid_cols = {r[0] for r in cursor.fetchall()}
            provided_keys = list(data.keys())
            insert_items = [(k, v) for k, v in data.items() if k in valid_cols]
            ignored = [k for k in provided_keys if k not in valid_cols]
            if not insert_items:
                raise DavloInsertError(
                    f"No valid columns to insert. Provided: {provided_keys}. Available: {sorted(valid_cols)}"
                )
            cols = ', '.join(f"[{c}]" for c, _ in insert_items)
            placeholders = ', '.join(['?'] * len(insert_items))
            values = [v for _, v in insert_items]
            insert_sql = f"INSERT INTO {safe_table} ({cols}) VALUES ({placeholders})"
            cursor.execute(insert_sql, values)
            conn.commit()
            result.update({
                'success': True,
                'rowcount': cursor.rowcount,
                'used_columns': [c for c, _ in insert_items],
                'ignored_columns': ignored,
                'table': safe_table,
            })
        except DavloInsertError as de:
            result['error'] = str(de)
        except Exception as ex:
            result['error'] = f"Unexpected failure: {ex}"
        return pd.DataFrame([result])


# ---------------------------- Helpers ---------------------------- #
def _sanitize_table_name(table: str) -> str:
    """Validate and sanitize supplied table name.

    Acceptable patterns: table, schema.table. Each part must be alnum/underscore only.
    Returns quoted form [schema].[table] or [table].
    Raises ValueError on invalid input.
    """
    if not isinstance(table, str) or not table.strip():
        raise ValueError("table must be a non-empty string")
    parts = table.strip().split('.')
    if len(parts) not in (1, 2):
        raise ValueError("table must be in form 'table' or 'schema.table'")
    cleaned = []
    for p in parts:
        if not p.replace('_', '').isalnum():
            raise ValueError(f"Invalid identifier part: {p}")
        cleaned.append(f"[{p}]")
    return '.'.join(cleaned)


def _split_schema_table(safe_table: str):
    parts = safe_table.split('.')
    if len(parts) == 2:
        return parts[0].strip('[]'), parts[1].strip('[]')
    return None, parts[0].strip('[]')


_FORBIDDEN_IN_CLAUSE = {";", "--", "/*", "*/", "DROP", "INSERT", "DELETE", "UPDATE", "MERGE", "ALTER", "TRUNCATE"}

def _validate_optional_clause(clause: str) -> str:
    if clause is None:
        return ''
    if not isinstance(clause, str):
        raise ValueError("params must be a string")
    trimmed = clause.strip()
    if not trimmed:
        return ''
    upper = trimmed.upper()
    if not (upper.startswith("WHERE ") or upper.startswith("ORDER BY ") or upper.startswith("GROUP BY ")):
        raise ValueError("params must start with WHERE / ORDER BY / GROUP BY")
    for bad in _FORBIDDEN_IN_CLAUSE:
        if bad in upper:
            raise ValueError(f"Forbidden token in params: {bad}")
    # Basic safety: disallow multiple clauses concatenated
    if upper.count(' WHERE ') > 1:
        raise ValueError("params contains multiple WHERE clauses")
    return trimmed


# ---------------------------- Exceptions & Config Loader ---------------------------- #
class DavloError(Exception):
    """Base exception for Davlo client."""


class DavloInsertError(DavloError):
    """Raised for insert-related issues with helpful context."""

dav_client = DavloConfig()

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
