ALERT_LOOKBACK_WINDOW_IN_DAYS = 7

ENTITY_CLUSTER_BOTS = [("0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9", "ENTITY-CLUSTER")]

CONTRACT_SIMILARITY_BOTS = [("0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560", "NEW-SCAMMER-CONTRACT-CODE-HASH")]
CONTRACT_SIMILARITY_BOT_THRESHOLDS = [0.97]

FINDINGS_CACHE_BLOCK_KEY = "findings_cache_block_key"
FINDINGS_CACHE_ALERT_KEY = "findings_cache_alert_key"

ALERTED_CLUSTERS_KEY = "alerted_clusters_key"
ALERTED_CLUSTERS_QUEUE_SIZE = 250000
ALERTED_FP_CLUSTERS_KEY = "alerted_fp_addresses_key"
ALERTED_FP_CLUSTERS_QUEUE_SIZE = 10000

SIMILAR_CONTRACT_THRESHOLD = 0.9
TX_COUNT_FILTER_THRESHOLD = 2000  # ignore EOAs with tx count larger than this threshold to mitigate FPs

BASE_BOTS = [("0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c", "SEAPORT-PHISHING-TRANSFER", "PassThrough", "SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER"),  # seaport orders
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PERMITTED-ERC20-TRANSFER", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SUSPICIOUS-TRANSFER", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-SCAM-PERMIT", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SCAM-APPROVAL", "Combination", ""),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SCAM-CREATOR-APPROVAL", "Combination", ""),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SCAM-TRANSFER", "Combination", ""),  # ice phishing
             ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SCAM-CREATOR-TRANSFER", "Combination", ""),  # ice phishing
             ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", "Combination", ""),  # tornado cash withdrawl
             ("0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a", "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION", "Combination", ""),  # Tornado Cash Funded Account Interaction
             ("0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2", "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH", "Combination", ""),  # money laundering
             ("0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4", "forta-text-messages-possible-hack", "Combination", ""),  # forta-text-messages-agent
             ("0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION", "Combination", ""),  # Flashbot
             ("0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3", "UNVERIFIED-CODE-CONTRACT-CREATION", "Combination", ""),  # unverified contract creation
             ("0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895", "AE-MALICIOUS-ADDR", "Combination", ""),  # malicious address bot
             ("0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba", "SLEEPMINT-3", "Combination", "SCAM-DETECTOR-SLEEP-MINTING"),  # sleep minting
             ("0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb", "CEX-FUNDING-1", "Combination", ""),  # CEX Funding
             ("0x47b86137077e18a093653990e80cb887be98e7445291d8cf811d3b2932a3c4d2", "AK-AZTEC-PROTOCOL-DEPOSIT-EVENT", "Combination", ""),  # Aztec MoneyLaundering
             ("0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0", "UMBRA-RECEIVE", "Combination", ""),  # umbra receive
             ("0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46", "MALICIOUS-ACCOUNT-FUNDING", "Combination", ""),  # Malicious Account Funding
             ("0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e", "FUNDING-CHANGENOW-NEW-ACCOUNT", "Combination", ""),  # Changenow funding
             ("0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad", "SUSPICIOUS-TOKEN-CONTRACT-CREATION", "Combination", ""),  # Malicious Token ML Model
             ("0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799", "ATTACK-DETECTOR-1", "PassThrough", "SCAM-DETECTOR-1"),  # Attack Detector V3 - has lots of rug pulls and rake tokens
             ("0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502", "ADDRESS-POISONING", "PassThrough", "SCAM-DETECTOR-ADDRESS-POISONING"),  # Malicious Token ML Model
             ("0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502", "ADDRESS-POISONING-LOW-VALUE", "PassThrough", "SCAM-DETECTOR-ADDRESS-POISONING"),  # Malicious Token ML Model
             ("0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502", "ADDRESS-POISONING-FAKE-TOKEN", "PassThrough", "SCAM-DETECTOR-ADDRESS-POISONING"),  # Malicious Token ML Model
             ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-1", "PassThrough", "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING"),  # Native ice phishing with a social eng component (aka a function parameter)
             ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-4", "PassThrough", "SCAM-DETECTOR-NATIVE-ICE-PHISHING"),  # Native ice phishing without a social eng component
             ("0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732", "NFT-WASH-TRADE", "PassThrough", "SCAM-DETECTOR-WASH-TRADE"),  # wash trading bot
             ("0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560", "NEW-SCAMMER-CONTRACT-CODE-HASH", "PassThrough", "SCAM-DETECTOR-SIMILAR-CONTRACT"),  # contract similarity bot
             ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-5", "PassThrough", "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING"),  # Native ice phishing using soc eng contract (static)
             ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-6", "PassThrough", "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING"),  # Native ice phishing using soc eng contract (dynamic)
             ("0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15", "HARD-RUG-PULL-1", "PassThrough", "SCAM-DETECTOR-HARD-RUG-PULL"),  # hard rug pull bot
             ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
             ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
             ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-POOL-REMOVAL && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
             ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-POOL-REMOVAL", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
             ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-POOL-REMOVAL && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
             ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-POOL-REMOVAL", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot (when rug pull actually happens)
             ("0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11", "RAKE-TOKEN-CONTRACT-1", "PassThrough", "SCAM-DETECTOR-RAKE-TOKEN"),  # rake token
        ]

# BASE_BOTS = [
#            ("0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732", "NFT-WASH-TRADE", "Preparation"),  # wash trading bot
             
#         ]
