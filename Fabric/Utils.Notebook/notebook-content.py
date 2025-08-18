# Fabric notebook source

# METADATA ********************

# META {
# META   "kernel_info": {
# META     "name": "synapse_pyspark"
# META   },
# META   "dependencies": {
# META     "lakehouse": {
# META       "default_lakehouse": "d30e8df9-0551-46b6-805e-cfc054b195be",
# META       "default_lakehouse_name": "lh_davlo_config",
# META       "default_lakehouse_workspace_id": "086e574d-a26f-4a9d-a34d-af3125924f27",
# META       "known_lakehouses": [
# META         {
# META           "id": "d30e8df9-0551-46b6-805e-cfc054b195be"
# META         }
# META       ]
# META     }
# META   }
# META }

# MARKDOWN ********************

# # Utils
# xxx

# CELL ********************

%pip install pandas --quiet

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# CELL ********************

import pandas as pd
import json
from datetime import datetime, timedelta

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# MARKDOWN ********************

# ## Data security
# xxx

# CELL ********************

%run nb_utils_data_security

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# CELL ********************

# MAGIC %%sql
# MAGIC -- Create ManagedWorkspaces table in Fabric Lakehouse
# MAGIC CREATE TABLE ManagedWorkspaces (
# MAGIC     WorkspaceID STRING,
# MAGIC     WorkspaceName STRING,
# MAGIC     WorkspaceURI STRING,
# MAGIC     IsActive BOOLEAN,
# MAGIC     CreatedOn timestamp,
# MAGIC     ChangedOn timestamp,
# MAGIC     OwnerEmail STRING,
# MAGIC     Department STRING
# MAGIC )
# MAGIC USING DELTA;


# METADATA ********************

# META {
# META   "language": "sparksql",
# META   "language_group": "synapse_pyspark"
# META }
