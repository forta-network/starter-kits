DEBUG_ALERT_ENABLED = False
ENABLE_METAMASK_CONSUMPTION = True

ALERT_LOOKBACK_WINDOW_IN_DAYS = 7

ENTITY_CLUSTER_BOTS = [("0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9", "ENTITY-CLUSTER")]

CONTRACT_SIMILARITY_BOTS = [("0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560", "NEW-SCAMMER-CONTRACT-CODE-HASH")]
CONTRACT_SIMILARITY_BOT_THRESHOLDS = [0.97]

EOA_ASSOCIATION_BOTS = [("0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848", "SCAMMER-LABEL-PROPAGATION-1")]
EOA_ASSOCIATION_BOT_THRESHOLDS = [0.0]

ENCRYPTED_BOTS = {"0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534": "BLOCKSEC"}

FINDINGS_CACHE_BLOCK_KEY = "findings_cache_block_key"
FINDINGS_CACHE_TRANSACTION_KEY = "findings_cache_transaction_key"
FINDINGS_CACHE_ALERT_KEY = "findings_cache_alert_key"

ALERTED_ENTITIES_ML_KEY = "alerted_entities_ml_per_alert_id_key"
ALERTED_ENTITIES_ML_QUEUE_SIZE = 100000
ALERTED_ENTITIES_PASSTHROUGH_KEY = "alerted_entities_passthrough_per_alert_id_key"
ALERTED_ENTITIES_PASSTHROUGH_QUEUE_SIZE = 75000
ALERTED_ENTITIES_SCAMMER_ASSOCIATION_KEY = "alerted_entities_scammer_association_per_alert_id_key"
ALERTED_ENTITIES_SCAMMER_ASSOCIATION_QUEUE_SIZE = 100000
ALERTED_ENTITIES_SIMILAR_CONTRACT_KEY = "alerted_entities_similar_contract_per_alert_id_key"
ALERTED_ENTITIES_SIMILAR_CONTRACT_QUEUE_SIZE = 100000
ALERTED_ENTITIES_MANUAL_KEY = "alerted_entities_manual_per_alert_id_key"
ALERTED_ENTITIES_MANUAL_QUEUE_SIZE = 100000
ALERTED_ENTITIES_MANUAL_METAMASK_KEY = "alerted_entities_manual_metamask_per_alert_id_key"
ALERTED_ENTITIES_MANUAL_METAMASK_QUEUE_SIZE = 250000
ALERTED_FP_CLUSTERS_KEY = "alerted_fp_addresses_per_alert_id_key"
ALERTED_FP_CLUSTERS_QUEUE_SIZE = 10000

TX_COUNT_FILTER_THRESHOLD = 2000  # ignore EOAs with tx count larger than this threshold to mitigate FPs
CONTRACTS_TX_COUNT_FILTER_THRESHOLD = 5000 # ignore EOAs that have deployed a contract with tx count larger than this threshold to mitigate FPs

SCAM_DETECTOR_BOT_ID = '0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23'
SCAM_DETECTOR_BETA_BOT_ID = '0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8'
SCAM_DETECTOR_BETA_ALT_BOT_ID = '0xb27524b92bf27e6aa499a3a7239232ad425219b400d3c844269f4a657a4adf03'

BASE_BOTS = [("0x15e9b3cd277d3be1fcfd5e23d61b3496026d8c3d9c98ef47a48e37b3c216ab9f", "nft-phishing-sale", "PassThrough", "SCAM-DETECTOR-FRAUDULENT-NFT-ORDER"),  # seaport orders
             ("0x15e9b3cd277d3be1fcfd5e23d61b3496026d8c3d9c98ef47a48e37b3c216ab9f", "nft-possible-phishing-transfer", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PERMITTED-ERC20-TRANSFER", "Combination", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
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
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PULL-SWEEPTOKEN", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-OPENSEA-PROXY-UPGRADE", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PIG-BUTCHERING", "PassThrough", "SCAM-DETECTOR-PIG-BUTCHERING"),  # ice phishing
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ZERO-NONCE-ALLOWANCE", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ZERO-NONCE-ALLOWANCE-TRANSFER", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),  # ice phishing
                ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", "Combination", ""),  # tornado cash withdrawl
                ("0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a", "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION", "Combination", ""),  # Tornado Cash Funded Account Interaction
                ("0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2", "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH", "Combination", ""),  # money laundering
                ("0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4", "forta-text-messages-possible-hack", "Combination", ""),  # forta-text-messages-agent
                ("0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION", "Combination", ""),  # Flashbot
                ("0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3", "UNVERIFIED-CODE-CONTRACT-CREATION", "Combination", ""),  # unverified contract creation
                ("0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba", "SLEEPMINT-3", "Combination", "SCAM-DETECTOR-SLEEP-MINTING"),  # sleep minting
                ("0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb", "CEX-FUNDING-1", "Combination", ""),  # CEX Funding
                ("0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0", "UMBRA-RECEIVE", "Combination", ""),  # umbra receive
                ("0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e", "FUNDING-CHANGENOW-NEW-ACCOUNT", "Combination", ""),  # Changenow funding
                ("0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad", "SUSPICIOUS-TOKEN-CONTRACT-CREATION", "Combination", ""),  # Malicious Token ML Model
                ("0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502", "ADDRESS-POISONING", "PassThrough", "SCAM-DETECTOR-ADDRESS-POISONING"),  # Malicious Token ML Model
                ("0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502", "ADDRESS-POISONING-LOW-VALUE", "PassThrough", "SCAM-DETECTOR-ADDRESS-POISONING"),  # Malicious Token ML Model
                ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-1", "PassThrough", "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING"),  # Native ice phishing with a social eng component (aka a function parameter)
                ("0x8732dbb3858d65844d940f5de3705b4161c05258bdfedf1ff5afb6683e1274e5", "NFT-WASH-TRADE", "PassThrough", "SCAM-DETECTOR-WASH-TRADE"),  # wash trading bot maintained by nethermind
                ("0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732", "NFT-WASH-TRADE", "Combination", ""),  # wash trading bot - for ML bot; need to replace after retraining
                ("0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560", "NEW-SCAMMER-CONTRACT-CODE-HASH", "PassThrough", "SCAM-DETECTOR-SIMILAR-CONTRACT"),  # contract similarity bot
                ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-5", "PassThrough", "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING"),  # Native ice phishing using soc eng contract (static)
                ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-6", "PassThrough", "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING"),  # Native ice phishing using soc eng contract (dynamic)
                ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-8", "PassThrough", "SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING"),  # Native ice phishing using soc eng contract (dynamic)
                ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-9", "PassThrough", "SCAM-DETECTOR-NATIVE-ICE-PHISHING"),  # Native ice phishing multicall
                ("0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15", "HARD-RUG-PULL-1", "PassThrough", "SCAM-DETECTOR-HARD-RUG-PULL"),  # hard rug pull bot
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION && SOFT-RUG-PULL-SUS-POOL-REMOVAL", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-POOL-REMOVAL && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-POOL-REMOVAL", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-POOL-REMOVAL && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-POOL-REMOVAL", "PassThrough", "SCAM-DETECTOR-SOFT-RUG-PULL"),  # soft rug pull bot (when rug pull actually happens)
                ("0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127", "IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR", "PassThrough", "SCAM-DETECTOR-IMPERSONATING-TOKEN"),  # IMPERSONATING token
                ("0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058", "FLD_FUNDING", "Combination", ""),
                ("0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058", "FLD_Laundering", "Combination", ""),
                ("0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058", "FLD_NEW_FUNDING", "Combination", ""),
                ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-2", "Combination", ""),
                ("0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0", "NIP-4", "Combination", ""),
                ("0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8", "ANOMALOUS-TOKEN-TRANSFERS-TX", "Combination", ""),
                ("0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8", "INVALID-TOKEN-TRANSFERS-TX", "Combination", ""),
                ("0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8", "NORMAL-TOKEN-TRANSFERS-TX", "Combination", ""),
                ("0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba", "SLEEPMINT-1", "Combination", ""),
                ("0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION", "Combination", ""),
                ("0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", "SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH", "Combination", ""),
                ("0x15e9b3cd277d3be1fcfd5e23d61b3496026d8c3d9c98ef47a48e37b3c216ab9f", "indexed-nft-sale", "Combination", ""),
                ("0x15e9b3cd277d3be1fcfd5e23d61b3496026d8c3d9c98ef47a48e37b3c216ab9f", "nft-sale", "Combination", ""),
                ("0x15e9b3cd277d3be1fcfd5e23d61b3496026d8c3d9c98ef47a48e37b3c216ab9f", "nft-sold-above-floor-price", "Combination", ""),
                ("0x15e9b3cd277d3be1fcfd5e23d61b3496026d8c3d9c98ef47a48e37b3c216ab9f", "scammer-nft-trader", "Combination", ""),
                ("0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127", "IMPERSONATED-TOKEN-DEPLOYMENT", "Combination", ""),
                ("0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac", "LARGE-PROFIT", "Combination", ""),
                ("0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad", "NON-MALICIOUS-TOKEN-CONTRACT-CREATION", "Combination", ""),
                ("0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad", "SAFE-TOKEN-CONTRACT-CREATION", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-APPROVAL-FOR-ALL", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-PERMIT", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-PERMIT-INFO", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-APPROVALS", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO", "Combination", ""),
                ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SUSPICIOUS-APPROVAL", "Combination", ""),
                ("0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e", "FUNDING-CHANGENOW-LOW-AMOUNT", "Combination", ""),
                ("0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502", "ADDRESS-POISONING-ZERO-VALUE", "PassThrough", "SCAM-DETECTOR-ADDRESS-POISONING"),
                ("0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c", "SAFE-CONTRACT-CREATION", "Combination", ""),
                ("0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c", "SUSPICIOUS-CONTRACT-CREATION", "Combination", ""),
                ("0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b", "MEV-ACCOUNT", "Combination", ""),
                ("0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb", "LARGE-TRANSFER-OUT", "Combination", ""),
                ("0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOTS-TRANSACTIONS", "Combination", ""),
                ("0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15", "HARD-RUG-PULL-HONEYPOT-DYNAMIC", "Combination", ""),
                ("0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "POSITIVE-REPUTATION-1", "Combination", ""),
                ("0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f", "ASSET-DRAINED", "Combination", ""),
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION", "Combination", ""),
                ("0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4", "SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE", "Combination", ""),
                ("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "omitted", "Combination", ""),
                ("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "Ice-phishing-web", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),
                ("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "Fraudulent-nft-order", "PassThrough", "SCAM-DETECTOR-FRAUDULENT-NFT-ORDER"),
                ("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "Ice-phishing", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"), 
                ("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "Native-ice-phishing", "PassThrough", "SCAM-DETECTOR-NATIVE-ICE-PHISHING"), 
                ("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "Address-poisoning", "PassThrough", "SCAM-DETECTOR-ADDRESS-POISONING"), 
                ("0x112eaa6e9d705efb187be0073596e1d149a887a88660bd5491eece44742e738e", "VICTIM-NOTIFIER-EOA", "PassThrough", "SCAM-DETECTOR-UNKNOWN"),
                ("0x112eaa6e9d705efb187be0073596e1d149a887a88660bd5491eece44742e738e", "SCAM-NOTIFIER-EOA", "PassThrough", "SCAM-DETECTOR-UNKNOWN"),
                ("0xd45f7183783f5893f4b8e187746eaf7294f73a3bb966500d237bd0d5978673fa", "PHISHING-TOKEN-NEW", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"),
                ("0x715c40c11a3e24f3f21c3e2db1c109bba358ccfcbceada84ee1e0f4dba4410e7", "GAS-ANOMALOUS-LARGE-CONSUMPTION", "PassThrough", "SCAM-DETECTOR-GAS-MINTING"),
                ("0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11", "RAKE-TOKEN-CONTRACT-1", "PassThrough", "SCAM-DETECTOR-RAKE-TOKEN"),  # rake token
                ("0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848", "SCAMMER-LABEL-PROPAGATION-1", "PassThrough", "SCAM-DETECTOR-SCAMMER-ASSOCIATION"),  # local model
                ("0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848", "SCAMMER-LABEL-PROPAGATION-2", "PassThrough", "SCAM-DETECTOR-SCAMMER-ASSOCIATION"),  # global model
                ("0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8", "SOCIAL-ENG-CONTRACT-CREATION", "PassThrough", "SCAM-DETECTOR-UNKNOWN"),  # social engineering contract
                ("0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8", "SOCIAL-ENG-CONTRACT-CREATION-NULL-ADDRESS", "PassThrough", "SCAM-DETECTOR-UNKNOWN"),  # social engineering contract
                ("0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8", "SOCIAL-ENG-EOA-CREATION-NULL-ADDRESS", "PassThrough", "SCAM-DETECTOR-UNKNOWN"),  # social engineering contract
                ("0x42dbb60aa8059dd395df9f66230f63852856f7fdd0d6d3fc55b708f8f84a3f47", "CHAINPATROL-SCAM-ASSET", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"), # chainpatrol bot
                ("0x9ba66b24eb2113ca3217c5e02ac6671182247c354327b27f645abb7c8a3e4534", "Phishing-drainer", "PassThrough", "SCAM-DETECTOR-ICE-PHISHING"), 
                ("0x154da7913f0d42dc50b5007fc4950ac0ab1f399023a0703784fd461d874100c5", "FORTA-1", "PassThrough", "SCAM-DETECTOR-UNKNOWN"),  # forta twitter bot
                ]

# model information
# double check whether the above subscriptions include the below model features; otherwise the feature would never be populated
MODEL_NAME = "v3_scammer_model.joblib"
MODEL_FEATURES = ['0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732_NFT-WASH-TRADE',
       '0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732_count',
       '0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732_uniqalertid_count',
       '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_FLD_FUNDING',
       '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_FLD_Laundering',
       '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_FLD_NEW_FUNDING',
       '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_count',
       '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_uniqalertid_count',
       '0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0_NIP-1',
       '0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0_NIP-2',
       '0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0_NIP-4',
       '0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0_NIP-6',
       '0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0_count',
       '0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0_uniqalertid_count',
       '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_ANOMALOUS-TOKEN-TRANSFERS-TX',
       '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_INVALID-TOKEN-TRANSFERS-TX',
       '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_NORMAL-TOKEN-TRANSFERS-TX',
       '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_count',
       '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_uniqalertid_count',
       '0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba_SLEEPMINT-1',
       '0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba_count',
       '0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba_uniqalertid_count',
       '0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11_RAKE-TOKEN-CONTRACT-1',
       '0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11_count',
       '0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11_uniqalertid_count',
       '0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99_SUSPICIOUS-CONTRACT-CREATION',
       '0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99_SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH',
       '0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99_count',
       '0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99_uniqalertid_count',
       '0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2_POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH',
       '0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2_count',
       '0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2_uniqalertid_count',
       '0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3_UNVERIFIED-CODE-CONTRACT-CREATION',
       '0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3_count',
       '0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3_uniqalertid_count',
       '0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac_count', # To be updated
       '0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac_indexed-nft-sale',
       '0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac_nft-possible-phishing-transfer',
       '0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac_nft-sale',
       '0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac_nft-sold-above-floor-price',
       '0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac_scammer-nft-trader',
       '0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac_uniqalertid_count',
       '0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a_TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION',
       '0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a_count',
       '0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a_uniqalertid_count',
       '0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127_IMPERSONATED-TOKEN-DEPLOYMENT',
       '0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127_count',
       '0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127_uniqalertid_count',
       '0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac_LARGE-PROFIT',
       '0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac_count',
       '0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac_uniqalertid_count',
       '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_NON-MALICIOUS-TOKEN-CONTRACT-CREATION',
       '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_SAFE-TOKEN-CONTRACT-CREATION',
       '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_SUSPICIOUS-TOKEN-CONTRACT-CREATION',
       '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_count',
       '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_uniqalertid_count',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-APPROVAL-FOR-ALL',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC20-PERMIT',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC20-PERMIT-INFO',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVALS',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-APPROVAL',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-TRANSFER',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_count',
       '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_uniqalertid_count',
       '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e_FUNDING-CHANGENOW-LOW-AMOUNT',
       '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e_count',
       '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e_uniqalertid_count',
       '0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502_ADDRESS-POISONING',
       '0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502_ADDRESS-POISONING-FAKE-TOKEN',
       '0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502_ADDRESS-POISONING-ZERO-VALUE',
       '0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502_count',
       '0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502_uniqalertid_count',
       '0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c_SAFE-CONTRACT-CREATION',
       '0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c_SUSPICIOUS-CONTRACT-CREATION',
       '0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c_count',
       '0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c_uniqalertid_count',
       '0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b_MEV-ACCOUNT',
       '0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b_count',
       '0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b_uniqalertid_count',
       '0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb_LARGE-TRANSFER-OUT',
       '0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb_count',
       '0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb_uniqalertid_count',
       '0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_FLASHBOTS-TRANSACTIONS',
       '0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_count',
       '0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_uniqalertid_count',
       '0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15_HARD-RUG-PULL-1',
       '0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15_HARD-RUG-PULL-HONEYPOT-DYNAMIC',
       '0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15_count',
       '0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15_uniqalertid_count',
       '0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f_POSITIVE-REPUTATION-1',
       '0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f_count',
       '0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f_uniqalertid_count',
       '0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_ASSET-DRAINED',
       '0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_count',
       '0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_uniqalertid_count',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-POOL-REMOVAL',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_SOFT-RUG-PULL-SUS-POOL-REMOVAL',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_SOFT-RUG-PULL-SUS-POOL-REMOVAL && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_count',
       '0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4_uniqalertid_count',
       '0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb_CEX-FUNDING-1',
       '0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb_count',
       '0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb_uniqalertid_count']
MODEL_ALERT_THRESHOLD_LOOSE = 0.70  # precison of 42/48 (88%) on test set; 183/192 (95%) on train set
MODEL_ALERT_THRESHOLD_STRICT = 0.896  # precision of 100% on test and train set


# utilized for passthrough and combiner labels
# these are sourced from manual analysis and represent precision - last updated 6/15/2023
CONFIDENCE_MAPPINGS = {
        "sleep-minting": 0.7,
        "ice-phishing": 0.91,
        "wash-trading": 0.98, 
        "fraudulent-nft-order": 0.86,
        "native-ice-phishing-social-engineering": 0.94,
        "native-ice-phishing":  0.85,
        "pig-butchering":  0.99,
        "hard-rug-pull": 0.99,
        "soft-rug-pull": 0.96,
        "rake-token": 0.99,
        "address-poisoning": 0.99,
        "address-poisoner": 0.85,
        "impersonating-token": 0.99,
        "attack-stages": 0.25,
        "similar-contract": 0.99,
        "scammer-deployed-contract": 0.99,
        "scammer-association": 0.60,
        "private-key-compromise": 0.4,
        "gas-minting": 0.9,
        "unknown": 0.99
}


# for handleTx to identify new contract deployments, which are indirect
SWAP_FACTORY_ADDRESSES = {
  1: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",  # uniswap
  43114: "0x794C07912474351b3134E6D6B3B7b3b4A07cbAAa",  # uniswap
  56: "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",  # pancakeswap
  137: "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32",  # quickswap
  250: "0x514053a5bAa4CFef80aA7C2A55d2c8365a5B5eAd",  # sushiswap
  42161: "0x1F98431c8aD98523631AE4a59f267346ea31F984",  # uniswap
  10: "0x1F98431c8aD98523631AE4a59f267346ea31F984"  # uniswap
}
PAIRCREATED_EVENT_ABI = '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"token0","type":"address"},{"indexed":true,"internalType":"address","name":"token1","type":"address"},{"indexed":false,"internalType":"address","name":"pair","type":"address"},{"indexed":false,"internalType":"uint256","name":"","type":"uint256"}],"name":"PairCreated","type":"event"}'
POOLCREATED_EVENT_ABI = '{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"token0","type":"address"},{"indexed":true,"internalType":"address","name":"token1","type":"address"},{"indexed":true,"internalType":"uint24","name":"fee","type":"uint24"},{"indexed":false,"internalType":"int24","name":"tickSpacing","type":"int24"},{"indexed":false,"internalType":"address","name":"pool","type":"address"}],"name":"PoolCreated","type":"event"}'



# BASE_BOTS = [
#            ("0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732", "NFT-WASH-TRADE", "Preparation"),  # wash trading bot
             
#         ]
