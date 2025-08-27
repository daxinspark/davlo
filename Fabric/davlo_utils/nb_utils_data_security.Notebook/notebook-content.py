# Fabric notebook source

# METADATA ********************

# META {
# META   "kernel_info": {
# META     "name": "jupyter",
# META     "jupyter_kernel_name": "python3.11"
# META   },
# META   "dependencies": {}
# META }

# MARKDOWN ********************

# ## Data Security
# 
# This guide explains the column-level encryption utilities for pandas DataFrames included in this repo. It covers what they do, how secure they are, the available options, and how to use them.
# 
# ### What it is
# 
# - Encrypts selected DataFrame columns using AES-256-GCM (AEAD) with keys derived via HKDF (SHA-256).
# - Binds each ciphertext to its column name and version via AEAD Associated Data (AAD) to prevent misuse or swapping across columns.
# - Supports two modes:
# 	- Randomized (default): strong privacy; identical plaintexts produce different ciphertexts.
# 	- Deterministic: equality-preserving; identical plaintexts produce identical ciphertexts for joins/group-bys.
# - Optional per-column HMAC tokens ("<col>_hash") to support lookups or checks without decryption.
# 
# ### Security model (at a glance)
# 
# - AES-256-GCM provides confidentiality and integrity. Any tampering results in decryption failure (InvalidTag).
# - Keys are derived from a provided root key using HKDF with mode-specific context ("info").
# 	- Randomized mode uses a per-run random salt + per-cell random nonces.
# 	- Deterministic mode uses a fixed HKDF (salt=None) and derives nonces via HMAC for stability.
# - AAD includes `col:<column>|<version>` so tokens can’t be replayed under a different column name.
# - Deterministic mode intentionally leaks equality across rows and runs; use only when required.
# 
# ### API
# 
# ```
# column_level_encryption(
# 	df: pd.DataFrame,
# 	encryption_key: str,
# 	encryption_columns: list[str],
# 	hashing_option: bool = False,
# 	encryption_randomize: bool = True,
# ) -> pd.DataFrame
# 
# column_level_decryption(
# 	df: pd.DataFrame,
# 	encryption_key: str,
# 	encryption_columns: list[str],
# ) -> pd.DataFrame
# ```
# 
# Parameters
# - df: Input DataFrame.
# - encryption_key: High-entropy secret (recommend 32 random bytes, base64-encoded). Manage via a secret store.
# - encryption_columns: List of column names to encrypt/decrypt.
# - hashing_option: When True, adds `<col>_hash` tokens aligned with the chosen mode.
# - encryption_randomize:
# 	- True (default): randomized encryption, best privacy. Token prefix `v1$`.
# 	- False: deterministic encryption for equality operations. Token prefix `v1d$`.


# CELL ********************

module = "column_level_data_security"

if not davlo_eligible(module):
    mssparkutils.notebook.exit(str(f"Not eligible for {module}"))

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python",
# META   "frozen": false,
# META   "editable": false
# META }

# CELL ********************

!pip install cryptography --quiet

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

import os
import base64
import json
from typing import List
import pandas as pd
import time

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# MARKDOWN ********************

# ### Encrypt
# xxx

# CELL ********************

def column_level_encryption(
    df: pd.DataFrame,
    encryption_key: str,
    encryption_columns: List[str],
    hashing_option: bool = False,
    encryption_randomize: bool = True,
) -> pd.DataFrame:
    """
    Encrypt specified DataFrame columns with AES-256-GCM.

    - encryption_randomize=True (default): per-run salt + per-cell random nonce (same as before). Token "v1$...".
    - encryption_randomize=False: deterministic encryption (same value -> same ciphertext). Token "v1d$...".
      Nonce is HMAC-derived from plaintext + AAD, keys come from HKDF with salt=None.

    Hashing (optional):
    - Randomized: HMAC over plaintext with per-run salt (varies each run).
    - Deterministic: HMAC over plaintext with fixed key (stable each run).
    """

    start = time.perf_counter()
    dav_client = DavloConfig()

    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a pandas.DataFrame")
    if not isinstance(encryption_columns, (list, tuple)) or not all(isinstance(c, str) for c in encryption_columns):
        raise TypeError("encryption_columns must be a list of column names")
    missing = [c for c in encryption_columns if c not in df.columns]
    if missing:
        raise ValueError(f"Columns not found: {missing}")

    VERSION_R = "v1"     # randomized
    VERSION_D = "v1d"    # deterministic
    NONCE_LEN = 12
    SALT_LEN = 16
    INFO_R = b"column-level-encryption:" + VERSION_R.encode("utf-8")
    INFO_D = b"column-level-encryption:" + VERSION_D.encode("utf-8")

    root_key_bytes = encryption_key.encode("utf-8")

    def _is_null(v) -> bool:
        try:
            return pd.isna(v)
        except Exception:
            return v is None

    def _serialize(v) -> bytes:
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        if isinstance(v, str):
            return v.encode("utf-8")
        return json.dumps(v, default=str, sort_keys=True, separators=(",", ":")).encode("utf-8")

    out = df.copy(deep=True)

    if encryption_randomize:
        # Per-run salt; same as existing behavior
        salt = os.urandom(SALT_LEN)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=INFO_R)
        km = hkdf.derive(root_key_bytes)
        enc_key = km[:32]
        mac_key = km[32:]
        aesgcm = AESGCM(enc_key)

        def _encrypt_cell(col_name: str, v):
            if _is_null(v):
                return v
            pt = _serialize(v)
            nonce = os.urandom(NONCE_LEN)
            aad = f"col:{col_name}|{VERSION_R}".encode("utf-8")
            ct = aesgcm.encrypt(nonce, pt, aad)
            payload = salt + nonce + ct
            return f"{VERSION_R}${base64.urlsafe_b64encode(payload).decode('ascii')}"

        def _hash_cell(col_name: str, v):
            if _is_null(v):
                return v
            pt = _serialize(v)
            aad = f"col:{col_name}|{VERSION_R}".encode("utf-8")
            h = hmac.HMAC(mac_key, hashes.SHA256())
            h.update(aad)
            h.update(b"\x00")
            h.update(pt)
            digest = h.finalize()
            payload = salt + digest
            return f"{VERSION_R}${base64.urlsafe_b64encode(payload).decode('ascii')}"
    else:
        # Deterministic: fixed HKDF (salt=None), HMAC-derived nonce
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=INFO_D)
        km = hkdf.derive(root_key_bytes)
        enc_key = km[:32]
        prf_key = km[32:]  # used to deterministically derive nonces and hashes
        aesgcm = AESGCM(enc_key)

        def _encrypt_cell(col_name: str, v):
            if _is_null(v):
                return v
            pt = _serialize(v)
            aad = f"col:{col_name}|{VERSION_D}".encode("utf-8")
            h = hmac.HMAC(prf_key, hashes.SHA256())
            h.update(b"nonce|")
            h.update(aad)
            h.update(b"\x00")
            h.update(pt)
            nonce = h.finalize()[:NONCE_LEN]
            ct = aesgcm.encrypt(nonce, pt, aad)
            payload = nonce + ct
            return f"{VERSION_D}${base64.urlsafe_b64encode(payload).decode('ascii')}"

        def _hash_cell(col_name: str, v):
            if _is_null(v):
                return v
            pt = _serialize(v)
            aad = f"col:{col_name}|{VERSION_D}".encode("utf-8")
            h = hmac.HMAC(prf_key, hashes.SHA256())
            h.update(b"hash|")
            h.update(aad)
            h.update(b"\x00")
            h.update(pt)
            digest = h.finalize()
            return f"{VERSION_D}${base64.urlsafe_b64encode(digest).decode('ascii')}"

    for col in encryption_columns:
        out[col] = out[col].apply(lambda v, c=col: _encrypt_cell(c, v)).astype("object")
        if hashing_option:
            out[f"{col}_hash"] = out[col].apply(lambda v, c=col: _hash_cell(c, v)).astype("object")

    dav_client.post(
        table = 'logging.ActivityLogEncryption',
        data = {
            "Process":"Encryption",
            "DurationMs":int((time.perf_counter() - start) * 1000),
            "RowsAffected":len(out),
            "EncryptedColumns":";".join(encryption_columns),
            "Success":True,
            "WorkspaceID": fabric.get_workspace_id()
        }
    )


    return out

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# MARKDOWN ********************

# ### Decrypt
# xxx

# CELL ********************

def column_level_decryption(
    df: pd.DataFrame,
    encryption_key: str,
    encryption_columns: List[str],
) -> pd.DataFrame:

    start = time.perf_counter()
    dav_client = DavloConfig()

    VERSION_R = "v1"
    VERSION_D = "v1d"
    NONCE_LEN = 12
    SALT_LEN = 16
    INFO_R = b"column-level-encryption:" + VERSION_R.encode("utf-8")
    INFO_D = b"column-level-encryption:" + VERSION_D.encode("utf-8")

    root_key_bytes = encryption_key.encode("utf-8")

    def _deserialize(pt: bytes):
        try:
            text = pt.decode("utf-8")
        except UnicodeDecodeError:
            return pt
        try:
            return json.loads(text)
        except Exception:
            return text

    def _parse_token(val: str):
        if not isinstance(val, str) or "$" not in val:
            return None, None
        ver, b64 = val.split("$", 1)
        if ver not in (VERSION_R, VERSION_D):
            return None, None
        try:
            payload = base64.urlsafe_b64decode(b64.encode("ascii"))
        except Exception:
            return None, None
        return ver, payload

    def _decrypt_value(token: str, aad_names: list[str]):
        ver, payload = _parse_token(token)
        if ver is None:
            return token  # passthrough

        if ver == VERSION_R:
            if len(payload) < SALT_LEN + NONCE_LEN + 16:
                raise ValueError("Malformed randomized payload")
            salt = payload[:SALT_LEN]
            nonce = payload[SALT_LEN:SALT_LEN + NONCE_LEN]
            ct = payload[SALT_LEN + NONCE_LEN:]
            hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=INFO_R)
            km = hkdf.derive(root_key_bytes)
            enc_key = km[:32]
            aesgcm = AESGCM(enc_key)
            last = None
            for name in aad_names:
                aad = f"col:{name}|{VERSION_R}".encode("utf-8")
                try:
                    pt = aesgcm.decrypt(nonce, ct, aad)
                    return _deserialize(pt)
                except Exception as e:
                    last = e
            raise InvalidTag("Authentication failed (randomized).") from last

        # Deterministic
        if len(payload) < NONCE_LEN + 16:
            raise ValueError("Malformed deterministic payload")
        nonce = payload[:NONCE_LEN]
        ct = payload[NONCE_LEN:]
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=INFO_D)
        km = hkdf.derive(root_key_bytes)
        enc_key = km[:32]
        aesgcm = AESGCM(enc_key)
        last = None
        for name in aad_names:
            aad = f"col:{name}|{VERSION_D}".encode("utf-8")
            try:
                pt = aesgcm.decrypt(nonce, ct, aad)
                return _deserialize(pt)
            except Exception as e:
                last = e
        raise InvalidTag("Authentication failed (deterministic).") from last

    out = df.copy(deep=True)
    for logical_col in encryption_columns:
        candidates = [logical_col, f"{logical_col}_encrypt"]
        enc_col = next((c for c in candidates if c in out.columns), None)
        if enc_col is None:
            raise ValueError(f"Column not found for decryption: {logical_col} (tried {candidates})")

        aad_candidates = [logical_col]
        if enc_col != logical_col:
            aad_candidates.append(enc_col)

        out[logical_col] = out[enc_col].apply(
            lambda v: v if pd.isna(v) else _decrypt_value(v, aad_candidates)
        )

    dav_client.post(
        table = 'logging.ActivityLogEncryption',
        data = {
            "Process":"Decryption",
            "DurationMs":int((time.perf_counter() - start) * 1000),
            "RowsAffected":len(out),
            "EncryptedColumns":";".join(encryption_columns),
            "Success":True,
            "WorkspaceID": fabric.get_workspace_id()
        }
    )


    return out

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# MARKDOWN ********************

# ## Encryption key rotation

# CELL ********************

from azure.identity import ClientSecretCredential

client_id = "efd3c00c-9dc3-41de-a13f-a121c4384b0d"  
encrypted_bytes = "\u007fgL\u0012{Ti\u001b{\u001f`AXuOId{eXprf\u001cEYCG~xO\u0018siC^EK\u0019n"  
tenant_id = "2b55fa1c-0add-4120-a8e4-9987abf4d504"
client_secret = (bytes([b ^ 42 for b in encrypted_bytes.encode("latin1")]).decode())
kv_uri = "https://kv-euw-davlo.vault.azure.net/"

credential = ClientSecretCredential(
    tenant_id=tenant_id,
    client_id=client_id,
    client_secret=client_secret
)


from azure.keyvault.secrets import SecretClient
secret_client = SecretClient(vault_url=kv_uri, credential=credential)



# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

def get_all_encryption_keys(credential:ClientSecretCredential, keyvault_uri:str):
    from azure.keyvault.secrets import SecretClient
    secret_client = SecretClient(vault_url=kv_uri, credential=credential)

    secrets_list = [
        secret.name
        for secret in secret_client.list_properties_of_secrets()
        if secret.name.startswith("ENCRYPTION-KEY")
    ]

    return secrets_list


def get_encryption_key(credential:ClientSecretCredential, keyvault_uri:str, key_name:str) -> str:
    from azure.keyvault.secrets import SecretClient
    try:
        secret_client = SecretClient(vault_url=keyvault_uri, credential=credential)
        secret = secret_client.get_secret(key_name).value
        secret_client.close()
    except Exception as e:
        print(e)
        try: secret_client.close() 
        except: None
        return ""

    return secret


def create_encryption_key():
    import base64, os
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def post_encryption_key(new_key:str, credential:ClientSecretCredential, keyvault_uri:str, key_name:str) -> bool:
    from azure.keyvault.secrets import SecretClient
    try:
        secret_client = SecretClient(vault_url=keyvault_uri, credential=credential)

        if key_name in get_all_encryption_keys(credential, keyvault_uri): return False
        
        secret = secret_client.set_secret(key_name, new_key)
        secret_client.close()
    except Exception as e:
        print(e)
        try: secret_client.close() 
        except: None
        return False

    return True


# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

value=get_encryption_key(
    credential=credential,
    keyvault_uri=kv_uri,
    key_name="ENCRYPTION-KEY-V1"
)
value

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

post_encryption_key(
    new_key=create_encryption_key(),
    credential=credential,
    keyvault_uri=kv_uri,
    key_name="ENCRYPTION-KEY-V1"
)

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }

# CELL ********************

def rotate_encryption_key():
    creds = get_credential_client

    

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }
