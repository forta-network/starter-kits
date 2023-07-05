MAX_NONCE = 500
MAX_AGE_IN_DAYS = 7
ONE_WAY_WEI_TRANSFER_THRESHOLD = 50000000000000000000  # 50 ETH

ALERTED_ADDRESSES_KEY = "alerted_addresses_key"
FINDINGS_CACHE_KEY = "findings_cache_key"
GRAPH_KEY = "graph_key"

NEW_FUNDED_MAX_NONCE = 1
NEW_FUNDED_MAX_WEI_TRANSFER_THRESHOLD = 1000000000000000000 # 1 ETH

S3_BUCKET= "fortaentitycluster"
S3_REGION="us-east-1"
DYNAMO_TABLE= "FORTA-ENTITY-CLUSTER"
DEV_DYNAMO_TABLE= "dev-javadox"
DYNAMO_REGION="us-west-1"
DYNAMO_MUTEX_TABLE_NAME = 'FortaEntityClusterMutex'

# if True  it will profile every transaction and dump it to entity_cluster_prof_stats file so can be viewed with snakeviz
PROFILING = False

# How many Transaction to wait before saving. configured as 6 blocks of ethereum
TX_SAVE_STEP = 150*6
# Timeout for w3 calls in seconds 
HTTP_RPC_TIMEOUT = 2
# timeout of the lock in the mutex db 10s
MUTEX_TIMEOUT_MILLIS=10*10000

