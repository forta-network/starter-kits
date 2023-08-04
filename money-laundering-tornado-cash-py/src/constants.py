# High thresholds are nearly 1M USD, medium thresholds are nearly 400K USD, and low thresholds are nearly 40K USD
TORNADO_CASH_TRANSFER_AMOUNT_THRESHOLDS = {1: {"high": 500, "medium": 200, "low": 20},
                                           56: {"high": 4000, "medium": 1600, "low": 160},
                                           42161: {"high": 500, "medium": 200, "low": 20},
                                           10: {"high": 500, "medium": 200, "low": 20},
                                           137: {"high": 1500000, "medium": 600000, "low": 60000}}


# how many accounts should be tracked by the bot in memory before dequeuing items
TORNADO_CASH_ACCOUNTS_QUEUE_SIZE = 10000

# Obtained from https://docs.tornado.cash/general/tornado-cash-smart-contracts#tornado-cash-classic-pools-contracts
TORNADO_CASH_ADDRESSES = {1: "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",  # Ethereum Mainnet - 100 ETH
                          56: "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # BSC - 100 BNB
                          42161: "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # ARBITRUM - 100 ETH
                          10: "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # OPTIMISM - 100 ETH
                          137: "0xa5C2254e4253490C54cef0a4347fddb8f75A4998"  # POLYGON - 100000 MATIC
                          }


TORNADO_CASH_DEPOSIT_TOPIC = '0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'
