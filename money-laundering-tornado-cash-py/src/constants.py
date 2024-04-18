from decimal import Decimal

# Obtained from https://docs.tornado.cash/general/tornado-cash-smart-contracts#tornado-cash-classic-pools-contracts
# Ethereum 100 eth: 0xa160cdab225685da1d56aa342ad8841c3b53f291
# Ethereum 10 eth: 0x910cbd523d972eb0a6f4cae4618ad62622b39dbf
# Ethereum 1 eth: 0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936

# BSC 100 bnb: 0x1e34a77868e19a6647b1f2f47b51ed72dede95dd
# BSC 10 bnb: 0x330bdfade01ee9bf63c209ee33102dd334618e0a
# BSC 1 bnb: 0xd47438c816c9e7f2e2888e060936a499af9582b3

# Arbitrum 100 eth: 0x1e34a77868e19a6647b1f2f47b51ed72dede95dd
# Arbitrum 10 eth: 0x330bdfade01ee9bf63c209ee33102dd334618e0a
# Arbitrum 1 eth: 0xd47438c816c9e7f2e2888e060936a499af9582b3

# Optimism 100 eth: 0x1e34a77868e19a6647b1f2f47b51ed72dede95dd
# Optimism 10 eth: 0x330bdfade01ee9bf63c209ee33102dd334618e0a
# Optimism 1 eth: 0xd47438c816c9e7f2e2888e060936a499af9582b3

# Polygon 100000 matic: 0xa5c2254e4253490c54cef0a4347fddb8f75a4998
# Polygon 10000 matic: 0xaf4c0b70b2ea9fb7487c7cbb37ada259579fe040
# Polygon 1000 matic: 0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178
# Polygon 100 matic: 0x1e34a77868e19a6647b1f2f47b51ed72dede95dd

TORNADO_CASH_ADDRESSES = {"0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": Decimal("0.1"), "0x84443cfd09a48af6ef360c6976c5392ac5023a1f": Decimal("0.1"), "0xa160cdab225685da1d56aa342ad8841c3b53f291": 100, "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": 10, "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": 1, "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd": 100,
                          "0x330bdfade01ee9bf63c209ee33102dd334618e0a": 10, "0xd47438c816c9e7f2e2888e060936a499af9582b3": 1, "0xa5c2254e4253490c54cef0a4347fddb8f75a4998": 100000, "0xaf4c0b70b2ea9fb7487c7cbb37ada259579fe040": 10000, "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178": 1000}


TORNADO_CASH_DEPOSIT_TOPIC = '0xa945e51eec50ab98c161376f0db4cf2aeba3ec92755fe2fcd388bdbbb80ff196'
