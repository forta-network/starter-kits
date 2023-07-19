"""Default values for the options / filters"""

# FILTERS #####################################################################

TARGET_CONTRACT = '' # leave empty to disable the filtering by contract, otherwise enter an address like '0x767fe9edc9e0df98e07454847909b5e959d7ca0e'
TARGET_TOKEN = '' # leave empty to disable the filtering by token, otherwise enter an address like '0x767fe9edc9e0df98e07454847909b5e959d7ca0e'
MIN_TRANSFER_COUNT = 8
MIN_TRANSFER_TOTAL_ERC20 = 0
MIN_TRANSFER_TOTAL_NATIVE = 10**18 # 1 ETH
MIN_CONFIDENCE_SCORE = 0.6
MIN_MALICIOUS_SCORE = 0.5

# INDICATORS ##################################################################

MAX_BATCHING_FEE = 2 * 10 ** 17 # 0.2 ETH: the balance of the batching contract should not increase more than a fee
