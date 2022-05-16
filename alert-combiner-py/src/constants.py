DATE_LOOKBACK_WINDOW_IN_DAYS = 1
ADDRESS_QUEUE_SIZE = 10000

AGENT_IDS = ["0x6a0960a22bb752532b68c266dfa507849009283bf11f086095f3504211c2b5fa",  # ice phishing
             "0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99",  # suspicious contract creation
             "0xaedda4252616d971d570464a3ae4a9f0a9d72a57d8581945fff648d03cd30a7d",  # blocklisted account tx
             "0x4cc272e78a685e27abcccdb40578f91f43baecc43e3c465460991a9dcdcb9756",  # tornado cash withdrawl
             "0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a",  # tornado cash funding
             "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9",  # reentrancy
             "0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2",  # money laundering
             "0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7",  # high gas usage
             "0xd92be855c14c12cf7ca43315deeaafbee8ec8dc732b0a452c9a6e2165dc554b0",  # high gas price
             "0xbf953b115fd214e1eb5c4d6f556ea30f0df47bd86bf35ce1fdaeff03dc7df5b7",  # high value transaction
             "0x6c268855e6235395b7efbd7b556f4a00858906e7f303a3cc87c2cb1a12a82332",  # txt messaging bot
             "0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3"  # unverified contract creation
             ]

ALERT_ID_STAGE_MAPPING = {"FORTA-PHISHING-ALERT": "Preparation",  # ice phishing
                          "SUSPICIOUS-CONTRACT-CREATION": "Preparation",  # suspicious contract creation
                          "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH": "Preparation",  # suspicious contract creation
                          "FORTA-BLOCKLIST-ADDR-TX": "Preparation",  # blocklisted accountn tx
                          "AE-FORTA-0": "Funding",  # tornado cash withdrawl
                          "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION": "Funding",  # tornado cash funding
                          "NETHFORTA-25": "Exploitation",  # reentrancy
                          "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH": "MoneyLaundering",  # money laundering
                          "IMPOSSIBLE-2": "Exploitation",  # high gas usage (but really also high gas price)
                          "AE-ANOMALOUS-GAS": "Exploitation",  # high gas price
                          "NETHFORTA-2": "Exploitation",  # high value transaction
                          "forta-text-messages-possible-hack": "Exploitation",  # txt messaging bot
                          "UNVERIFIED-CODE-CONTRACT-CREATION": "Preparation"  # unverified contract creation
                          }
