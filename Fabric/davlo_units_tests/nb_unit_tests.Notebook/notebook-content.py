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

def encrypt_decrypt():
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

encrypt_decrypt()

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }
