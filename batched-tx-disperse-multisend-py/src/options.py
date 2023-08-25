"""Default values for the options / filters"""

# FILTERS #####################################################################

MIN_TRANSFER_COUNT = 8
MIN_TRANSFER_TOTAL_ERC20 = 0
MIN_TRANSFER_TOTAL_NATIVE = 10**18 # 1 ETH
MIN_CONFIDENCE_SCORE = 0.6
MIN_MALICIOUS_SCORE = 0.5

# STATS #######################################################################

ALERT_HISTORY_SIZE = 2048 # in number of transactions recorded

# INDICATORS ##################################################################

MAX_BATCHING_FEE = {
	1: 2 * 10 ** 17, # 0.2 ETH: the balance of the batching contract should not increase more than a fee
	10: 2 * 10 ** 17, # 0.2 ETH
	56: 2 * 10 ** 18, # 2 BNB
	61: 2 * 10 ** 17, # 0.2 ETH
	137: 5 * 10 ** 20, # 500 MATIC
	250: 1.5 * 10 ** 21, # 1500 FTM
	42161: 2 * 10 ** 17, # 0.2 ETH
	43114: 3 * 10 ** 19, # 30 AVAX
}
