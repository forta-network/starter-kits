BOT_ID = "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9"
MAX_NONCE = 500
MAX_AGE_IN_DAYS = 7
ONE_WAY_WEI_TRANSFER_THRESHOLD = 50000000000000000000  # 50 ETH

ALERTED_ADDRESSES_KEY = "alerted_addresses_key"
GRAPH_KEY = "graph_key"

NEW_FUNDED_MAX_NONCE = 1
NEW_FUNDED_MAX_WEI_TRANSFER_THRESHOLD = 1000000000000000000 # 1 ETH

S3_BUCKET= "prod-research-bot-data"
S3_REGION="us-east-1"

DYNAMO_TABLE= "prod-research-bot-data"
TEST_TAG= "test"
PROD_TAG= "prod"
DYNAMO_REGION="us-east-1"
DYNAMODB_PRIMARY_KEY = 'itemId'
DYNAMODB_SORT_KEY = 'sortKey'
DYNAMODB_TTL_KEY = 'expiresAt'

# if True  it will profile every transaction and dump it to entity_cluster_prof_stats file so can be viewed with snakeviz
PROFILING = False

# How many Transaction to wait before saving. configured as 6 blocks of ethereum
TX_SAVE_STEP = 150*6
# Timeout for w3 calls in seconds 
HTTP_RPC_TIMEOUT = 2
# timeout of the lock in the mutex db 10s
MUTEX_TIMEOUT_MILLIS = 10 * 10000
MALICIOUS_SMART_CONTRACT_BOT_ID = (
    "0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c"
)
SEVERITY_ALERT_FILTER = "HIGH"

CLUSTER_SENDER = True
