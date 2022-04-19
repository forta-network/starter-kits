CONTRACT_SLOT_ANALYSIS_DEPTH = 20  # how many slots should be read to extract contract addresses from created contract

TORNADO_CASH_FUNDED_ACCOUNTS_QUEUE_SIZE = 10000  # how many accounts should be held by the bot in memory before dequeuing items

# Obtained from https://docs.tornado.cash/general/tornado-cash-smart-contracts#tornado-cash-classic-pools-contracts
TORNADO_CASH_ADDRESSES = ["0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc",  # Ethereum Mainnet - 0.1 ETH
                          "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936",  # Ethereum Mainnet - 1 ETH
                          "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",  # Ethereum Mainnet - 10 ETH
                          "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",  # Ethereum Mainnet - 100 ETH
                          "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F",  # ARBITRUM - 0.1 ETH
                          "0xd47438C816c9E7f2E2888E060936a499Af9582b3",  # ARBITRUM - 1 ETH
                          "0x330bdFADE01eE9bF63C209Ee33102DD334618e0a",  # ARBITRUM - 10 ETH
                          "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # ARBITRUM - 100 ETH
                          "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F",  # OPTIMISM - 0.1 ETH
                          "0xd47438C816c9E7f2E2888E060936a499Af9582b3",  # OPTIMISM - 1 ETH
                          "0x330bdFADE01eE9bF63C209Ee33102DD334618e0a",  # OPTIMISM - 10 ETH
                          "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # OPTIMISM - 100 ETH
                          "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F",  # BSC - 0.1 BNB
                          "0xd47438C816c9E7f2E2888E060936a499Af9582b3",  # BSC - 1 BNB
                          "0x330bdFADE01eE9bF63C209Ee33102DD334618e0a",  # BSC - 10 BNB
                          "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # BSC - 100 BNB
                          "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD",  # POLYGON - 100 MATIC
                          "0xdf231d99Ff8b6c6CBF4E9B9a945CBAcEF9339178",  # POLYGON - 1000 MATIC
                          "0xaf4c0B70B2Ea9FB7487C7CbB37aDa259579fe040",  # POLYGON - 10000 MATIC
                          "0xa5C2254e4253490C54cef0a4347fddb8f75A4998"  # POLYGON - 100000 MATIC
                          ]
