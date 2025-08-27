# Fabric notebook source

# METADATA ********************

# META {
# META   "kernel_info": {
# META     "name": "synapse_pyspark"
# META   },
# META   "dependencies": {}
# META }

# MARKDOWN ********************

# # Unit Tests
# xxx

# MARKDOWN ********************

# ### Import DavLo Utils

# CELL ********************

%run nb_utils_main

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# MARKDOWN ********************

# ### Data Security

# CELL ********************

def data_security():
    try:
        df = pd.DataFrame({
            "id": [1, 2, 3],
            "email": ["alice@example.com", "bob@example.com", "carol@example.com"],
            "salary": [85000, 92000, 101000],
        })
        display(df)

        # Generate a high-entropy root key (store/manage securely in practice)
        root_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
        print("Root key: ",root_key)

        # Encrypt selected columns
        encrypted_df = column_level_encryption(
            df=df,
            encryption_key=root_key,
            encryption_columns=["email", "salary"],
            hashing_option=False,
            encryption_randomize=True
        )

        display(encrypted_df.head())

        decrypt_df = column_level_decryption(
            df=encrypted_df,
            encryption_key=root_key,
            encryption_columns=["email", "salary"]
        )

        display(decrypt_df.head())
        print(f"\n\n")

        return True
    except Exception as e:
        print(str(e))
        return False

def data_security_big():
    import os, base64, random, string
    import pandas as pd
    import numpy as np

    try:

        # Assumes column_level_encryption and column_level_decryption are already imported.

        def random_str(n: int):
            alphabet = string.ascii_letters + string.digits + " _-"
            return "".join(random.choices(alphabet, k=n))
        
        rng = np.random.default_rng(42)
        
        rows = rng.integers(31000, 62100)
        big_len = 20480  # large string size

        encrypted_cols = [
            "enc_email", "enc_salary", "enc_code", "enc_amount", "enc_flag",
            "enc_notes", "enc_big1", "enc_big2", "enc_misc1", "enc_misc2"
        ]

        other_cols = [f"c{i}" for i in range(1, 21)]  # total 30 columns

        
        data = {}

        data["enc_email"] = [f"user{i}@example.com" for i in range(rows)]
        data["enc_salary"] = rng.integers(50_000, 200_000, size=rows)
        data["enc_code"] = rng.integers(1000, 9999, size=rows).astype(str)
        data["enc_amount"] = rng.normal(1000, 250, size=rows).round(2)
        data["enc_flag"] = rng.integers(0, 2, size=rows)
        data["enc_notes"] = [random_str(64) for _ in range(rows)]
        data["enc_big1"] = [random_str(big_len) for _ in range(rows)]
        data["enc_big2"] = [random_str(big_len) for _ in range(rows)]
        data["enc_misc1"] = [random_str(32) for _ in range(rows)]
        data["enc_misc2"] = [random_str(48) for _ in range(rows)]

        for c in other_cols:
            # simple mix
            if rng.integers(0, 2) == 0:
                data[c] = rng.integers(0, 1_000_000, size=rows)
            else:
                data[c] = [random_str(12) for _ in range(rows)]

        df = pd.DataFrame(data)
        display(df.head())

        root_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

        encrypted_df = column_level_encryption(
            df=df,
            encryption_key=root_key,
            encryption_columns=encrypted_cols,
            hashing_option=False,
            encryption_randomize=True
        )
        display(encrypted_df.head())

        decrypted_df = column_level_decryption(
            df=encrypted_df,
            encryption_key=root_key,
            encryption_columns=encrypted_cols
        )
        display(decrypted_df.head())

        print(f"\n\n")
        return True
    except Exception as e:
        print(e)
        return False

# data_security()
data_security_big()

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# MARKDOWN ********************

# ### Data Quality (Basic)

# CELL ********************

def dq_basic():
    try:
        # Sample DataFrame
        now = datetime.now(timezone.utc)
        df = pd.DataFrame({
            "id": [1, 2, 3, 4, 5],
            "age": [25, 42, 130, np.nan, 31],
            "email": ["a@example.com", "bademail", "c@example.com", None, "d@sample.org"],
            "status": ["active", "inactive", "unknown", "ACTIVE", "inactive"],
            "updated_at": [
                now - timedelta(minutes=5),
                now - timedelta(days=2),
                now - timedelta(hours=1),
                pd.NaT,
                now - timedelta(minutes=30),
            ],
        })

        # Rules
        config = {
            "row_validations": [
                {"id": "not_null_id", "type": "not_null", "column": "id", "severity": "error"},
                {"id": "range_age", "type": "range", "column": "age", "min": 0, "max": 120, "severity": "warn"},
                {"id": "regex_email", "type": "regex", "column": "email",
                    "pattern": r"^[^\s@]+@[^\s@]+\.[^\s@]+$", "case_insensitive": True, "severity": "warn"},
                {"id": "allowed_status", "type": "allowed_values", "column": "status",
                    "allowed": ["active", "inactive"], "case_sensitive": False, "severity": "error"},
            ],
            "dataset_checks": [
                {"id": "min_rows", "type": "row_count_min", "min": 3, "severity": "error"},
                {"id": "freshness_updated_at", "type": "freshness", "column": "updated_at",
                    "max_lag_minutes": 60 * 24, "severity": "warn"},
            ],
        }


        results = run_basic_dq(df, config=config, dataset_name="demo.customers").reset_index(drop=True)
        
        return results
    
    
    except Exception as e:
        print(str(e))
        return False
    

dq_basic()

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }
