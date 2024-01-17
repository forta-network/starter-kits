TEST_MODE = False  # The mode when the bot uses test database
TRANSFERS_TO_CONFIRM = 50  # Amount of transfers to check the address
NEWLY_CREATED_MAX_TRANSACTIONS_AMOUNT = 5  # Address is newly created if its number of txs is below this value
DEX_DISABLE = False  # Disables DEX-related alerts
INFO_ALERTS = False  # Disables INFO alerts
MIN_AGE_IN_DAYS = 5

DEFAULT_THRESHOLDS = {
    "TRANSFER_THRESHOLD_IN_USD": 10, # Bot doesn't emit alerts if value in usd is below this
    "FUNDING_CRITICAL": 10000000, # Critical th for funding
    "FUNDING_HIGH": 1000000, # High th for funding
    "FUNDING_MEDIUM": 100000, # Medium th for funding
    "FUNDING_LOW": 10000, # Low th for funding
    "LAUNDERING_CRITICAL": 10000000, # Critical th for laundering
    "LAUNDERING_HIGH": 1000000, # High th for laundering
    "LAUNDERING_MEDIUM": 100000, # Medium th for laundering
    "LAUNDERING_LOW": 10000 # Low` th for laundering
}

L2_THRESHOLDS = {
    "TRANSFER_THRESHOLD_IN_USD": 3, # Bot doesn't emit alerts if value in usd is below this
    "FUNDING_CRITICAL": 3000000, # Critical th for funding
    "FUNDING_HIGH": 300000, # High th for funding
    "FUNDING_MEDIUM": 30000, # Medium th for funding
    "FUNDING_LOW": 3000, # Low th for funding
    "LAUNDERING_CRITICAL": 3000000, # Critical th for laundering
    "LAUNDERING_HIGH": 300000, # High th for laundering
    "LAUNDERING_MEDIUM": 30000, # Medium th for laundering
    "LAUNDERING_LOW": 3000 # Low` th for laundering
}

BLOCKS_IN_MEMORY_VALUES = {
    1: 50,
    10: 4000,
    56: 3000,
    137: 4000,
    250: 10000,
    42161: 50000,
    43114: 5000
}

MIXER_ADDRESSES = {1: ["0x4025ee6512dbbda97049bcf5aa5d38c54af6be8a"], 42161: ["0x20c2a9430baa7251eb9143cbe80ac3968893d06c", "0x5ad95c537b002770a39dea342c4bb2b68b1497aa"]}
