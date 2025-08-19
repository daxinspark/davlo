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
        print(df)

        # Generate a high-entropy root key (store/manage securely in practice)
        root_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
        print(root_key)

        # Encrypt selected columns
        encrypted_df = column_level_encryption(
            df=df,
            encryption_key=root_key,
            encryption_columns=["email", "salary"],
            hashing_option=False,
            encryption_randomize=True
        )

        print(encrypted_df.head())

        decrypt_df = column_level_decryption(
            df=encrypted_df,
            encryption_key=root_key,
            encryption_columns=["email", "salary"]
        )

        print(decrypt_df.head())

        return True
    except Exception as e:
        print(str(e))
        return False

data_security()

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
