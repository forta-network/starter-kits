DATE_LOOKBACK_WINDOW_IN_DAYS = 1
ADDRESS_QUEUE_SIZE = 10000

BOT_IDS = ["0xd9fe61cfe875470b80318a96cc0a94ba3adbe1eb4a14827fa018f14925e7da64",  # ice phishing
             "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99",  # suspicious contract creation
             "0xaedda4252616d971d570464a3ae4a9f0a9d72a57d8581945fff648d03cd30a7d",  # blocklisted account tx
             "0x4cc272e78a685e27abcccdb40578f91f43baecc43e3c465460991a9dcdcb9756",  # tornado cash withdrawl
             "0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a",  # Tornado Cash Funded Account Interaction
             "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9",  # reentrancy
             "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2",  # money laundering
             "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7",  # high gas usage
             "0xe27867c40008e0e3533d6dba7d3c1f26a61a3923bc016747d131f868f8f34555",  # high gas price
             "0xbf953b115fd214e1eb5c4d6f556ea30f0df47bd86bf35ce1fdaeff03dc7df5b7",  # high value transaction
             "0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4",  # forta-text-messages-agent
             "0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa",  # Transaction Volume Anomaly Detection
             "0x55636f5577694c83b84b0687eb77863850c50bd9f6072686c8463a0cbc5566e0",  # Flashloan Detection Bot
             "0x2c8452ff81b4fa918a8df4441ead5fedd1d4302d7e43226f79cb812ea4962ece",  # Large Mint Borrow Volume Anomaly Detection
             "0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127",  # Token Impersonation
             "0x0f21668ebd017888e7ee7dd46e9119bdd2bc7f48dbabc375d96c9b415267534c",  # Smart Price Change Bot
             "0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3"  # unverified contract creation
            ]

ALERT_ID_STAGE_MAPPING = {"ICE-PHISHING-PREV-APPROVED-TRANSFERED": "Exploitation",  # ice phishing
                          "ICE-PHISHING-HIGH-NUM-APPROVALS": "Preparation",  # ice phishing
                          "SUSPICIOUS-CONTRACT-CREATION": "Preparation",  # suspicious contract creation
                          "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH": "Preparation",  # suspicious contract creation
                          "FORTA-BLOCKLIST-ADDR-TX": "Preparation",  # blocklisted accountn tx
                          "AE-FORTA-0": "Funding",  # tornado cash withdrawl
                          "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION": "Funding",  # tornado cash funding
                          "NETHFORTA-25": "Exploitation",  # reentrancy
                          "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH": "MoneyLaundering",  # money laundering
                          "IMPOSSIBLE-2": "Exploitation",  # high gas usage (but really also high gas price)
                          "FORTA-2": "Exploitation",  # high gas price
                          "NETHFORTA-2": "Exploitation",  # high value transaction
                          "forta-text-messages-possible-hack": "Exploitation",  # txt messaging bot
                          "SUCCESSFUL-INTERNAL-TRANSACTION-VOL-INCREASE": "Exploitation",  # Transaction Volume Anomaly Detection
                          "SUCCESSFUL-TRANSACTION-VOL-INCREASE": "Exploitation",  # Transaction Volume Anomaly Detection
                          "FAILED-TRANSACTION-VOL-INCREASE": "Exploitation",  # Transaction Volume Anomaly Detection
                          "FAILED-TRANSACTION-VOL-INCREASE": "Exploitation",  # Transaction Volume Anomaly Detection
                          "FLASHLOAN-ATTACK": "Exploitation",  # Flashloan Detection Bot
                          "HIGH-MINT-VALUE": "Exploitation",  # Large Mint Borrow Volume Anomaly Detection
                          "HIGH-BORROW-VALUE": "Exploitation",  # Large Mint Borrow Volume Anomaly Detection
                          "IMPERSONATED-TOKEN-DEPLOYMENT": "Preparation",  # Token Impersonation
                          "SMART-PRICE-CHANGES": "Preparation",  # Smart Price Change Bot
                          "UNVERIFIED-CODE-CONTRACT-CREATION": "Preparation"  # unverified contract creation
                          }
