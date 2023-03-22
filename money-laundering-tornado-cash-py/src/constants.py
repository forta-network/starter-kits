BLOCK_RANGE = {1: 240, 56: 1200, 42161: 3600, 10: 300, 137: 1300}  # what block range should be utilized to assess the TORNADO_CASH_TRANSFER_COUNT_THRESHOLD; about an hour


# how many tornado cash transfers should be in a block range to be considered suspicious; currently configured to be about 1M USD
TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_ETH = 3  # 1M USD / (100 ETH * 3000 USD)
TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_MATIC = 75  # 1M USD / (10000 MATIC * 1.35 USD)
TORNADO_CASH_TRANSFER_COUNT_THRESHOLD_BSC = 25  # 1M USD / (100 BSC * 400 USD)
TORNADO_CASH_ACCOUNTS_QUEUE_SIZE = 10000  # how many accounts should be tracked by the bot in memory before dequeuing items

# Obtained from https://docs.tornado.cash/general/tornado-cash-smart-contracts#tornado-cash-classic-pools-contracts
TORNADO_CASH_ADDRESSES = {1: "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",  # Ethereum Mainnet - 100 ETH
                          56: "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # BSC - 100 BNB
                          42161: "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # ARBITRUM - 100 ETH
                          10: "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # OPTIMISM - 100 ETH
                          137: "0xa5C2254e4253490C54cef0a4347fddb8f75A4998"  # POLYGON - 100000 MATIC
                          }
TORNADO_CASH_DEPOSIT_SIZE = 100
TORNADO_CASH_DEPOSIT_SIZE_MATIC = 100000


TORNADO_CASH_DEPOSIT_TOPIC = '0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'
