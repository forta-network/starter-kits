ALERTS_LOOKBACK_WINDOW_IN_HOURS = 24
MIN_ALERTS_COUNT = 3
ANOMALY_SCORE_THRESHOLD_STRICT = 0.0000001
ANOMALY_SCORE_THRESHOLD_LOOSE = 0.0001


CONTRACT_CACHE_MAX_QUEUE_SIZE = 10000
ALERTED_CLUSTERS_MAX_QUEUE_SIZE = 10000
ALERTED_FP_CLUSTERS_QUEUE_SIZE = 10000
MANUALLY_ALERTED_ENTITIES_QUEUE_SIZE = 10000


DEFAULT_ANOMALY_SCORE = 0.001  # used if anomaly score is less or eq than 0

POLYGON_VALIDATOR_ALERT_COUNT_THRESHOLD = 40  # assume validator if alert count is larger than this threshold on polygon as the topic analysis seems unreliable

ATTACK_DETECTOR_BOT_ID = "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1"
ATTACK_DETECTOR_BETA_BOT_ID = "0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799"

ENTITY_CLUSTER_BOT = "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9"
ENTITY_CLUSTER_BOT_ALERT_ID = "ENTITY-CLUSTER"

VICTIM_IDENTIFICATION_BOT = "0x441d3228a68bbbcf04e6813f52306efcaf1e66f275d682e62499f44905215250"
VICTIM_IDENTIFICATION_BOT_ALERT_IDS = ["VICTIM-IDENTIFIER-PREPARATION-STAGE", "VICTIM-IDENTIFIER-EXPLOITATION-STAGE"]

TX_COUNT_FILTER_THRESHOLD = 500  # ignore EOAs with tx count larger than this threshold to mitigate FPs
FP_MITIGATION_BOTS = [("0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b", "MEV-ACCOUNT"),
                      ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH-HIGH"),
                      ("0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "POSITIVE-REPUTATION-1"),
                      ("0xe04b3fa79bd6bc6168a211bcec5e9ac37d5dd67a41a1884aa6719f8952fbc274", "VICTIM-NOTIFICATION-1")
                      ]

ALERTED_CLUSTERS_FP_MITIGATED_KEY = "alerted_clusters_fp_mitigated_key"
ALERTED_CLUSTERS_STRICT_KEY = "alerted_clusters_strict_key"
ALERTED_CLUSTERS_LOOSE_KEY = "alerted_clusters_loose_key"
ALERTED_FP_CLUSTERS_KEY = "alerted_fp_clusters_key"
MANUALLY_ALERTED_ENTITIES_KEY = "manually_alerted_entities_key"
FINDINGS_CACHE_BLOCK_KEY = "findings_cache_block_key"

LUABASE_QUERY_FREQUENCY_IN_HOURS = 4

# for the highly precise bots, we lower our threshold for alerting to 2 stages or 3 individual alerts; anomaly score is ignored
HIGHLY_PRECISE_BOTS = [("0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c", "SUSPICIOUS-CONTRACT-CREATION", "Preparation"),  # suspicious contract creation ML
                       ("0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabd3f9f6", "AK-ATTACK-SIMULATION-0", "Preparation"),  # attack simulation
                       ("0xda967b32461c6cd3280a49e8b5ff5b7486dbd130f3a603089ed4a6e3b03070e2", "SUSPICIOUS-FLASHLOAN-CONTRACT-CREATION", "Preparation"),  # suspicious-flashloan-contract-creation
                       ("0xb31f0db68c5231bad9c00877a3141da353970adcc14e1efe5b14c4d2d93c787f", "AK-ATTACK-SIMULATION-0", "Preparation"),  # attack simulation targeted
                       ("0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac", "LARGE-PROFIT", "Exploitation"),  # large profit
                       ]

# will filter EOAs associated with alerts from end user attack bots (will emit those as ATTACK-DETECTOR-6 alertId (beta only))
END_USER_ATTACK_BOTS = ["0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15",  # hard rug pull
                        "0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4",  # soft rug pull
                        "0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11",  # rake token
                        "0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127",  # impersonating token contract
                        "0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1",  # soft rug pull
                        ]
END_USER_ATTACK_CLUSTERS_KEY="end_user_attack_clusters_key"


VICTIM_IDENTIFICATION_BOT = "0x441d3228a68bbbcf04e6813f52306efcaf1e66f275d682e62499f44905215250"
VICTIM_IDENTIFICATION_BOT_ALERT_IDS = ["VICTIM-IDENTIFIER-PREPARATION-STAGE", "VICTIM-IDENTIFIER-EXPLOITATION-STAGE"]

BASE_BOTS = [("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS", "Exploitation"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PERMITTED-ERC20-TRANSFER", "Preparation"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SUSPICIOUS-TRANSFER", "Preparation"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS", "Preparation"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS", "Preparation"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "Preparation"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL", "Preparation"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL", "Preparation"),  # ice phishing
             ("0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", "Preparation"),  # suspicious contract creation
             ("0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH", "Preparation"),  # suspicious contract creation
             ("0x0e82982faa7878af3fad8ddf5042762a3b78d8949da2e301f1adfedc973f25ea", "EXPLOITER-ADDR-TX", "Preparation"),  # blocklisted account tx
             ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", "Funding"),  # tornado cash withdrawl
             ("0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9", "NETHFORTA-25", "Exploitation"),  # reentrancy
             ("0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2", "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH", "MoneyLaundering"),  # money laundering
             ("0xe27867c40008e0e3533d6dba7d3c1f26a61a3923bc016747d131f868f8f34555", "FORTA-2", "Exploitation"),  # high gas price
             ("0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4", "forta-text-messages-possible-hack", "MoneyLaundering"),  # forta-text-messages-agent
             ("0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa", "SUCCESSFUL-INTERNAL-TRANSACTION-VOL-INCREASE", "Exploitation"),  # Transaction Volume Anomaly Detection
             ("0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa", "SUCCESSFUL-TRANSACTION-VOL-INCREASE", "Exploitation"),  # Transaction Volume Anomaly Detection
             ("0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa", "FAILED-TRANSACTION-VOL-INCREASE", "Exploitation"),  # Transaction Volume Anomaly Detection
             ("0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa", "FAILED-INTERNAL-TRANSACTION-VOL-INCREASE", "Exploitation"),  # Transaction Volume Anomaly Detection
             ("0x55636f5577694c83b84b0687eb77863850c50bd9f6072686c8463a0cbc5566e0", "FLASHLOAN-ATTACK", "Exploitation"),  # Flashloan Detection Bot
             ("0x55636f5577694c83b84b0687eb77863850c50bd9f6072686c8463a0cbc5566e0", "FLASHLOAN-ATTACK-WITH-HIGH-PROFIT", "Exploitation"),  # Flashloan Detection Bot
             ("0x2c8452ff81b4fa918a8df4441ead5fedd1d4302d7e43226f79cb812ea4962ece", "HIGH-MINT-VALUE", "Exploitation"),  # Large Mint Borrow Volume Anomaly Detection
             ("0x2c8452ff81b4fa918a8df4441ead5fedd1d4302d7e43226f79cb812ea4962ece", "HIGH-BORROW-VALUE", "Exploitation"),  # Large Mint Borrow Volume Anomaly Detection
             ("0x0f21668ebd017888e7ee7dd46e9119bdd2bc7f48dbabc375d96c9b415267534c", "SMART-PRICE-CHANGES", "Exploitation"),  # Smart Price Change Bot
             ("0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", "Exploitation"),  # Flashbot
             ("0xfcf3ee41d04eee52f7944387010bc8aa6f22d54c36576c9a05db7e6cafda41f9", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: polygon (ether) - Ethereum Mainnet
             ("0xca504ee43501fe7c20084aa3112f8f57dd8c1e0e8a85d3884b66c252d6fc4f5b", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: polygon (ERC20) - Ethereum Mainnet
             ("0xa4b00d881c92526ef9a1db39cd3da2b7f32958eab2d7bb807546b7fd1a520748", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Avalanche - Ethereum Mainnet
             ("0x942c63db47285d28f01fba0a4e998f815f9784bf246fd981694fd1bcbc0e75c8", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum (Ether Gateway) - Ethereum Mainnet
             ("0x6f07249485378615abb12b352f7f0e9c68e6bab2de57475b963445e5639fced3", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum (ERC20) - Ethereum Mainnet
             ("0x4db4efcb505c19e076f1716f9c79d919ffb6a9802769b470e8d461066730c723", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum (Custom Gateway) - Ethereum Mainnet
             ("0x3f5d0e780a99c3058b58884844e4c71df34b2b739fd957847facc77f69e9f2cc", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Near/Aurora (Ether) - Ethereum Mainnet
             ("0x59cc55fc71711d81d99be376618e072fa34e1ddbda7401840542d9a584a78d08", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Near/Aurora (ERC20) - Ethereum Mainnet
             ("0x94f879d399f7fe7a06682d3abd58a955624ec08b9164c3838851bf6788d27e33", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Optimism V1 - Ethereum Mainnet
             ("0x5474812f32fa8206c178864bb7f95f737ab9cdb1e4125af2e86ad8dd8c5fbf31", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Optimism V2 - Ethereum Mainnet
             ("0x966929e33d640fead63ed3307ee802e1a45a5b3fabe8c796acf1d6bceb2c757e", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Harmony (Ether) - Ethereum Mainnet
             ("0xb9008e67f9a2425dc0e11f80d8d26880ec83880b9a169c9542a8e8d74337bb44", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Harmony (ERC20) - Ethereum Mainnet
             ("0xee1a0da8184264ed000c2d33f0a6e0df3aa43ad515c21b8320a00aea8c3ae457", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Harmony (BUSD) - Ethereum Mainnet
             ("0xe4cee68ce6b2d75ce17a2c727b92838a32e698eacb8848caaf6dade6f9330c12", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: xDai - Ethereum Mainnet
             ("0xdac6f4a16776648ef48b0c9850800507059e201139c2aa898b47d51ca0ebdaae", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Boba - Ethereum Mainnet
             ("0x742da1d837ac91905ec470d4e9d92e9c31a3104aa05a014a8f51ba355135bf8a", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Ronin - Ethereum Mainnet
             ("0x7b69174f32b91731d9b6245faaff945637c47f729a850fa312a27238bc98f383", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: THORChain - Ethereum Mainnet
             ("0xc10fe54aa93d43702eece2c439550ee079b5fa045aa03e08d47df6a3837e172b", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (ALTA) - BSC
             ("0xf947dfa6387710dd316cb9b1afec82d1f49d187426c8f6370000cddc2bec945d", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (USDC) - Ethereum Mainnet
             ("0x3d1242fb8af0cdd548e7b5e073534f298f7ddaebbafe931a3506ab0be0e67e87", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap  (Marlin POND) - FTM
             ("0x0b069cddde485c14666b35e13c0e0919e6bbb00ea7b0df711e45701b77841492", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (USDT) - Ethereum Mainnet
             ("0x19f468cbd6924a77fcb375a130e3bd1d3764366e42d4d7e6db0717a2229bfeba", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (USDT) - Polygon
             ("0xfbf1919aa876648dfe82315e529f1e7a98103a0b9ae38750e5e53b86fc80bd96", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Polygon zkEVM Bridge - Ethereum
             ("0xd2520a2b0f6dbbf815ba33376f36a406393508e709d8f50e13d4ebad43490a59", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Across Ethereum SpokePool - Ethereum
             ("0x5ab3964d3cb90ad68b6f307a7d5d3219b97c89c74e6aca261633af356ff73b4a", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Celer Network Original Token Vault V2 - Ethereum
             ("0x80749e2072849dacecaea54ec4d4b06d8da4e8c48ebf4cfe8fe9aeb0436a5776", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Celer Network Original Token Vault 2 - Ethereum
             ("0xd40554c0cc8393cb94aa22f4e10d67672a76f64112577f2d700b13bb08405926", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Celer Network cBridge V2 Bridge - Ethereum
             ("0x6639e223026aaec3c2c2e33c3a501f34e7a63e3c16d301f4f1ba0044135387e8", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol SNX Bridge - Ethereum 
             ("0x50679441079cf1f109311b5559c8141b30001cca0b0cee7e12067b1b4a5cf595", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol Matic Bridge - Ethereum
             ("0x2cb9c3b887edada37b9f198fdd84d12cfc5eeb81d4ea365e5e0097ba829ee2d9", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol ERC20 Bridge - Ethereum
             ("0xf8ca51a34b1d14819a01b731264d0b3356a186d7e42abb3b24eebd6848959823", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol DAI Bridge - Ethereum
             ("0xa8dfec4641f94e2682aacec00bf2b136053d1298f3aa9324213b01f48b3a013c", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol USDC Bridge - Ethereum
             ("0xdd72bddaeecbd1b4022c9275538fc4cb268b16980ad06428d697a36c1b61e208", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol USDT Bridge - Ethereum
             ("0x22673b42f62e43091c68378aa78f24a771f4f79042e2fb10eaedf53b1e07a75c", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol Ethereum Bridge - Ethereum
             ("0xc9887704aa0f002227b1461005d829e73095bc0263c31c631278780455ec8579", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain anyUSDT Bridge - Ethereum
             ("0x964cbcb16f9d3e1152a1b62638961fc4ec50fa4dddb253b48685ae3ae6cd175e", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain Fantom Bridge - Ethereum
             ("0x469d0e38ab07a111f951795c4507028d3ddd2f5bf40076c221a6cc3f0c8df2d4", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain anyETH Bridge - Ethereum
             ("0xd1e0a1991031894f79845fdb21cf36d80e5c35a11761d1b9acddc111ab3b3ab6", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Polygon Bridge - Ethereum
             ("0x7c67654fca8537473b9cebfa779885204cad216d4403d8cd93239cd2223b7e6d", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum DAI L1 Escrow - Ethereum
             ("0x0b5f51563d1ca3fb74a17af67db998cbc290fce19f1db716e7cc7cbfa1b2a9fc", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum Outbox - Ethereum
             ("0x61b3d0c3987c7d10de55711acd8e4f9892db924373a9d879605a5732ddde80c3", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum Delayed Inbox - Ethereum
             ("0xf193941c3ca27034453cdded1c270495fdd1319e71e026c44980ad35e52bf3f2", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Lido Optimism L1 ERC20 Token Bridge - Ethereum
             ("0x5514223d7d7bf9b1ec1eb5981eb471cb8eb7756fc615ca282de9a157b126694f", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Wormhole Portal Token Bridge - Ethereum
             ("0x98573cc633608a04c4a2aa963f58eaa5106fe20bbec33cd88fafeb5db293f2c0", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Near Rainbow Bridge - Ethereum
             ("0x259952782ab7cb9ca42068dde334da5b2d49bf40963f63b3ae97ab25bfbb1046", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate STG Bridge - Ethereum
             ("0x4e94072946966e73c7333042f9285d7a88cced482241873a476d2de37b3faead", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate FRAX Bridge - Ethereum
             ("0x7992c56564a94597eb3f952e0a603af471935c61d912f8ebf88f95f722df2df2", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate ETH Bridge - Ethereum
             ("0x19af004c822158e573668cf0bb39a2494faf471135676b08ab981327c44daf35", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate SUSDT Bridge - Ethereum
             ("0xf75e0714bd3a4f1df970c6d069ab3b457a2593846becef948751097d18d3286d", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate SUSDC Bridge - Ethereum
             ("0xbc1f5127113aeb6332451d5a5e51bf0bdd707c45eca26083e312c2066819a739", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Symbiosis Finance Bridge - Ethereum
             ("0x8c11dd81c639757b97f17de27a67d9b07bcd6c33f4b23ba94339728db460f03a", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Synapse Bridge - Ethereum
             ("0x67955dd1f25ab38cc5065d62453e73f77b8de43a79ad745c5f3816906c8fe815", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: Gnosis xDai-ETH Omni Bridge - Ethereum
             ("0x639c7768c5c28a1623aa0748aa5aa8c07be20542803820a2186179ac9715ff73", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: zkSync Era Diamond Bridge - Ethereum
             ("0xd2f60f7626eaeb15c4026578e28f799afb1587db3a8e4cb5bf2d42b54e13933d", "BALANCE-DECREASE-ASSETS-ALL-REMOVED", "Exploitation"),  # balance decrease for bridge: zkSync Era Bridge - Ethereum
             ("0xfcf3ee41d04eee52f7944387010bc8aa6f22d54c36576c9a05db7e6cafda41f9", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: polygon (ether) - Ethereum Mainnet
             ("0xca504ee43501fe7c20084aa3112f8f57dd8c1e0e8a85d3884b66c252d6fc4f5b", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: polygon (ERC20) - Ethereum Mainnet
             ("0xa4b00d881c92526ef9a1db39cd3da2b7f32958eab2d7bb807546b7fd1a520748", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Avalanche - Ethereum Mainnet
             ("0x942c63db47285d28f01fba0a4e998f815f9784bf246fd981694fd1bcbc0e75c8", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum (Ether Gateway) - Ethereum Mainnet
             ("0x6f07249485378615abb12b352f7f0e9c68e6bab2de57475b963445e5639fced3", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum (ERC20) - Ethereum Mainnet
             ("0x4db4efcb505c19e076f1716f9c79d919ffb6a9802769b470e8d461066730c723", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum (Custom Gateway) - Ethereum Mainnet
             ("0x3f5d0e780a99c3058b58884844e4c71df34b2b739fd957847facc77f69e9f2cc", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Near/Aurora (Ether) - Ethereum Mainnet
             ("0x59cc55fc71711d81d99be376618e072fa34e1ddbda7401840542d9a584a78d08", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Near/Aurora (ERC20) - Ethereum Mainnet
             ("0x94f879d399f7fe7a06682d3abd58a955624ec08b9164c3838851bf6788d27e33", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Optimism V1 - Ethereum Mainnet
             ("0x5474812f32fa8206c178864bb7f95f737ab9cdb1e4125af2e86ad8dd8c5fbf31", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Optimism V2 - Ethereum Mainnet
             ("0x966929e33d640fead63ed3307ee802e1a45a5b3fabe8c796acf1d6bceb2c757e", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Harmony (Ether) - Ethereum Mainnet
             ("0xb9008e67f9a2425dc0e11f80d8d26880ec83880b9a169c9542a8e8d74337bb44", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Harmony (ERC20) - Ethereum Mainnet
             ("0xee1a0da8184264ed000c2d33f0a6e0df3aa43ad515c21b8320a00aea8c3ae457", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Harmony (BUSD) - Ethereum Mainnet
             ("0xe4cee68ce6b2d75ce17a2c727b92838a32e698eacb8848caaf6dade6f9330c12", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: xDai - Ethereum Mainnet
             ("0xdac6f4a16776648ef48b0c9850800507059e201139c2aa898b47d51ca0ebdaae", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Boba - Ethereum Mainnet
             ("0x742da1d837ac91905ec470d4e9d92e9c31a3104aa05a014a8f51ba355135bf8a", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Ronin - Ethereum Mainnet
             ("0x7b69174f32b91731d9b6245faaff945637c47f729a850fa312a27238bc98f383", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: THORChain - Ethereum Mainnet
             ("0xc10fe54aa93d43702eece2c439550ee079b5fa045aa03e08d47df6a3837e172b", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (ALTA) - BSC
             ("0xf947dfa6387710dd316cb9b1afec82d1f49d187426c8f6370000cddc2bec945d", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (USDC) - Ethereum Mainnet
             ("0x3d1242fb8af0cdd548e7b5e073534f298f7ddaebbafe931a3506ab0be0e67e87", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap  (Marlin POND) - FTM
             ("0x0b069cddde485c14666b35e13c0e0919e6bbb00ea7b0df711e45701b77841492", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (USDT) - Ethereum Mainnet
             ("0x19f468cbd6924a77fcb375a130e3bd1d3764366e42d4d7e6db0717a2229bfeba", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain/Anyswap (USDT) - Polygon
             ("0xfbf1919aa876648dfe82315e529f1e7a98103a0b9ae38750e5e53b86fc80bd96", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Polygon zkEVM Bridge - Ethereum
             ("0xd2520a2b0f6dbbf815ba33376f36a406393508e709d8f50e13d4ebad43490a59", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Across Ethereum SpokePool - Ethereum
             ("0x5ab3964d3cb90ad68b6f307a7d5d3219b97c89c74e6aca261633af356ff73b4a", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Celer Network Original Token Vault V2 - Ethereum
             ("0x80749e2072849dacecaea54ec4d4b06d8da4e8c48ebf4cfe8fe9aeb0436a5776", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Celer Network Original Token Vault 2 - Ethereum
             ("0xd40554c0cc8393cb94aa22f4e10d67672a76f64112577f2d700b13bb08405926", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Celer Network cBridge V2 Bridge - Ethereum
             ("0x6639e223026aaec3c2c2e33c3a501f34e7a63e3c16d301f4f1ba0044135387e8", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol SNX Bridge - Ethereum 
             ("0x50679441079cf1f109311b5559c8141b30001cca0b0cee7e12067b1b4a5cf595", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol Matic Bridge - Ethereum
             ("0x2cb9c3b887edada37b9f198fdd84d12cfc5eeb81d4ea365e5e0097ba829ee2d9", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol ERC20 Bridge - Ethereum
             ("0xf8ca51a34b1d14819a01b731264d0b3356a186d7e42abb3b24eebd6848959823", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol DAI Bridge - Ethereum
             ("0xa8dfec4641f94e2682aacec00bf2b136053d1298f3aa9324213b01f48b3a013c", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol USDC Bridge - Ethereum
             ("0xdd72bddaeecbd1b4022c9275538fc4cb268b16980ad06428d697a36c1b61e208", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol USDT Bridge - Ethereum
             ("0x22673b42f62e43091c68378aa78f24a771f4f79042e2fb10eaedf53b1e07a75c", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Hop Protocol Ethereum Bridge - Ethereum
             ("0xc9887704aa0f002227b1461005d829e73095bc0263c31c631278780455ec8579", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain anyUSDT Bridge - Ethereum
             ("0x964cbcb16f9d3e1152a1b62638961fc4ec50fa4dddb253b48685ae3ae6cd175e", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain Fantom Bridge - Ethereum
             ("0x469d0e38ab07a111f951795c4507028d3ddd2f5bf40076c221a6cc3f0c8df2d4", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Multichain anyETH Bridge - Ethereum
             ("0xd1e0a1991031894f79845fdb21cf36d80e5c35a11761d1b9acddc111ab3b3ab6", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Polygon Bridge - Ethereum
             ("0x7c67654fca8537473b9cebfa779885204cad216d4403d8cd93239cd2223b7e6d", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum DAI L1 Escrow - Ethereum
             ("0x0b5f51563d1ca3fb74a17af67db998cbc290fce19f1db716e7cc7cbfa1b2a9fc", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum Outbox - Ethereum
             ("0x61b3d0c3987c7d10de55711acd8e4f9892db924373a9d879605a5732ddde80c3", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Arbitrum Delayed Inbox - Ethereum
             ("0xf193941c3ca27034453cdded1c270495fdd1319e71e026c44980ad35e52bf3f2", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Lido Optimism L1 ERC20 Token Bridge - Ethereum
             ("0x5514223d7d7bf9b1ec1eb5981eb471cb8eb7756fc615ca282de9a157b126694f", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Wormhole Portal Token Bridge - Ethereum
             ("0x98573cc633608a04c4a2aa963f58eaa5106fe20bbec33cd88fafeb5db293f2c0", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Near Rainbow Bridge - Ethereum
             ("0x259952782ab7cb9ca42068dde334da5b2d49bf40963f63b3ae97ab25bfbb1046", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate STG Bridge - Ethereum
             ("0x4e94072946966e73c7333042f9285d7a88cced482241873a476d2de37b3faead", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate FRAX Bridge - Ethereum
             ("0x7992c56564a94597eb3f952e0a603af471935c61d912f8ebf88f95f722df2df2", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate ETH Bridge - Ethereum
             ("0x19af004c822158e573668cf0bb39a2494faf471135676b08ab981327c44daf35", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate SUSDT Bridge - Ethereum
             ("0xf75e0714bd3a4f1df970c6d069ab3b457a2593846becef948751097d18d3286d", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Stargate SUSDC Bridge - Ethereum
             ("0xbc1f5127113aeb6332451d5a5e51bf0bdd707c45eca26083e312c2066819a739", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Symbiosis Finance Bridge - Ethereum
             ("0x8c11dd81c639757b97f17de27a67d9b07bcd6c33f4b23ba94339728db460f03a", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Synapse Bridge - Ethereum
             ("0x67955dd1f25ab38cc5065d62453e73f77b8de43a79ad745c5f3816906c8fe815", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: Gnosis xDai-ETH Omni Bridge - Ethereum
             ("0x639c7768c5c28a1623aa0748aa5aa8c07be20542803820a2186179ac9715ff73", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: zkSync Era Diamond Bridge - Ethereum
             ("0xd2f60f7626eaeb15c4026578e28f799afb1587db3a8e4cb5bf2d42b54e13933d", "BALANCE-DECREASE-ASSETS-PORTION-REMOVED", "Exploitation"),  # balance decrease for bridge: zkSync Era Bridge - Ethereum
             ("0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabd3f9f6", "AK-ATTACK-SIMULATION-0", "Preparation"),  # attack simulation
             ("0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3", "UNVERIFIED-CODE-CONTRACT-CREATION", "Preparation"),  # unverified contract creation
             ("0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8", "ANOMALOUS-TOKEN-TRANSFERS-TX", "Exploitation"),  # anomalous transaction bot
             ("0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895", "AE-MALICIOUS-ADDR", "Exploitation"),  # malicious address bot
             ("0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba", "SLEEPMINT-3", "Preparation"),  # sleep minting
             ("0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c", "SUSPICIOUS-CONTRACT-CREATION", "Preparation"),  # suspicious contract creation ML
             ("0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8", "SOCIAL-ENG-CONTRACT-CREATION", "Preparation"),  # social eng contract creation
             ("0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f", "ASSET-DRAINED", "Exploitation"),  # assets drained
             ("0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef", "AK-AZTEC-PROTOCOL-FUNDED-ACCOUNT-INTERACTION-0", "Exploitation"),  # Aztec Protocol funded account interacted with contract
             ("0xdccd708fc89917168f3a793c605e837572c01a40289c063ea93c2b74182cd15f", "AK-AZTEC-PROTOCOL-POSSIBLE-MONEY-LAUNDERING-NATIVE", "MoneyLaundering"),  # Aztec ML bot
             ("0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb", "CEX-FUNDING-1", "Funding"),  # CEX Funding
             ("0xdccd708fc89917168f3a793c605e837572c01a40289c063ea93c2b74182cd15f", "AK-AZTEC-PROTOCOL-DEPOSIT-EVENT", "Funding"),  # Aztec funding
             ("0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef", "AK-AZTEC-PROTOCOL-FUNDING", "Funding"),  # Aztec funding
             ("0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb", "LARGE-TRANSFER-OUT", "MoneyLaundering"),  # large native transfer out
             ("0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46", "MALICIOUS-ACCOUNT-FUNDING", "Funding"),  # Malicious Account Funding
             ("0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058", "FLD_NEW_FUNDING", "Funding"),  # New Account Funding
             ("0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058", "FLD_Laundering", "MoneyLaundering"),  # Laundering
             ("0x3858be37e155f84e8e0d6212db1b47d4e83b1d41e8a2bebecb902651ed1125d6", "NETHFORTA-1", "Exploitation"),  # high gas
             ("0xbdb84cba815103a9a72e66643fb4ff84f03f7c9a4faa1c6bb03d53c7115ddc4d", "NEGATIVE-ANGER-TEXT-MESSAGE", "MoneyLaundering"),  # txt msg sentiment analysis
             ("0xbdb84cba815103a9a72e66643fb4ff84f03f7c9a4faa1c6bb03d53c7115ddc4d", "NEGATIVE-DISGUST-TEXT-MESSAGE", "MoneyLaundering"),  # txt msg sentiment analysis
             ("0xbdb84cba815103a9a72e66643fb4ff84f03f7c9a4faa1c6bb03d53c7115ddc4d", "NEGATIVE-SADNESS-TEXT-MESSAGE", "MoneyLaundering"),  # txt msg sentiment analysis
             ("0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e", "FUNDING-CHANGENOW-NEW-ACCOUNT", "Funding"),  # change now bot
             ("0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad", "SUSPICIOUS-TOKEN-CONTRACT", "Preparation"),  # Malicious Token Contract ML Bot
             ("0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac", "LARGE-PROFIT", "Exploitation"),  # Large Profit Bot
             ("0x43d22eb5e1e3a2a98420f152825f215e6a756f32d73882ff31d8163652242832", "ROLE-CHANGE", "Preparation"),  # role change
             ("0xda967b32461c6cd3280a49e8b5ff5b7486dbd130f3a603089ed4a6e3b03070e2", "SUSPICIOUS-FLASHLOAN-PRICE-MANIPULATOR", "Preparation"),  # Suspicious flashloand contract creation
             ("0xb31f0db68c5231bad9c00877a3141da353970adcc14e1efe5b14c4d2d93c787f", "AK-ATTACK-SIMULATION-0", "Preparation"),  # attack simulation targeted
             ("0xabc0bb6fe5e0d0b981dec4aa2337ce91676358c6e8bf1fec06cc558f58c3694e", "UNUSUAL-NATIVE-SWAPS", "MoneyLaundering"),  # unusual native swaps
             ("0x644b77e0d77d68d3841a55843dcdd61840ad3ca09f7e1ab2d2f5191c35f4a998", "ABNORMAL-FUNCTION-CALL-DETECTED-1", "Exploitation"),  # abnormal function call
             ("0x644b77e0d77d68d3841a55843dcdd61840ad3ca09f7e1ab2d2f5191c35f4a998", "ABNORMAL-EMITTED-EVENT-DETECTED-1", "Exploitation"),  # abnormal function call
             ]
