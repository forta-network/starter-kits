# Obtained from https://docs.tornado.cash/general/tornado-cash-smart-contracts#tornado-cash-classic-pools-contracts
TORNADO_CASH_ADDRESSES = {1: ["0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936","0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc", "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf"],  # ethereum mainnet - 1 eth, 0.1 eth, 10 eth
                          56: ["0xd47438c816c9e7f2e2888e060936a499af9582b3", "0x84443cfd09a48af6ef360c6976c5392ac5023a1f", "0x330bdfade01ee9bf63c209ee33102dd334618e0a"],  # bsc - 1 bnb, 0.1 bnb, 10 bnb
                          42161: ["0xd47438c816c9e7f2e2888e060936a499af9582b3", "0x84443cfd09a48af6ef360c6976c5392ac5023a1f", "0x330bdfade01ee9bf63c209ee33102dd334618e0a"],  # arbitrum - 1 eth, 0.1 eth, 10eth
                          10: ["0xd47438c816c9e7f2e2888e060936a499af9582b3", "0x84443cfd09a48af6ef360c6976c5392ac5023a1f", "0x330bdfade01ee9bf63c209ee33102dd334618e0a"],  # optimism - 1 eth, 0.1 eth eth, 10 eth
                          137: ["0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178","0x1e34a77868e19a6647b1f2f47b51ed72dede95dd", "0xaf4c0b70b2ea9fb7487c7cbb37ada259579fe040"]  # polygon - 100 matic, 1000 matic, 10,000 matic
                          }

TORNADO_CASH_ADDRESSES_HIGH = {1: ["0xa160cdab225685da1d56aa342ad8841c3b53f291"],  # ethereum mainnet - 10 eth, 100 eth
                          56: ["0x1e34a77868e19a6647b1f2f47b51ed72dede95dd"],  # bsc - 10 bnb, 100 bnb
                          42161: ["0x1e34a77868e19a6647b1f2f47b51ed72dede95dd"],  # arbitrum - 100 eth
                          10: ["0x1e34a77868e19a6647b1f2f47b51ed72dede95dd"],  # optimism - 100 eth
                          137: ["0xa5c2254e4253490c54cef0a4347fddb8f75a4998"]  # polygon - 100,000 matic
                          }

TORNADO_CASH_WITHDRAW_TOPIC = '0xe9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931'
