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
    client_secret = config_file.get('sp').get('client_secret')

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


def query_config_db(query:str, conn= None) -> pd.DataFrame:

    if not conn:
        config_file = get_config_file(log=False)
        conn = connect_to_db(config_file=config_file)

    # Test query
    df = pd.read_sql(query, conn)   # here conn is your pyodbc connection object

    return df


# config_file = get_config_file(log=False)

# query_config_db(query = "SELECT TOP 5 name FROM sys.databases")

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
