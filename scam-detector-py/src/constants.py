DATE_LOOKBACK_WINDOW_IN_DAYS = 1
ADDRESS_QUEUE_SIZE = 10000

TX_COUNT_FILTER_THRESHOLD = 500  # ignore EOAs with tx count larger than this threshold to mitigate FPs

ENTITY_CLUSTER_BOT_DATE_LOOKBACK_WINDOW_IN_DAYS = 7
ENTITY_CLUSTER_BOT = "0xd3061db4662d5b3406b52b20f34234e462d2c275b99414d76dc644e2486be3e9"
ENTITY_CLUSTER_BOT_ALERT_ID = "ENTITY-CLUSTER" 

FP_MITIGATION_ADDRESSES = ["0x1e0049783f008a0085193e00003d00cd54003c71"  # open sea relayer
                          ]

FINDINGS_CACHE_KEY = "findings_cache_key"
ALERTED_CLUSTERS_KEY = "alerted_clusters_key"

BASE_BOTS = [("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS", "Exploitation"),  # ice phishing
           ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-PERMITTED-ERC20-TRANSFER", "Preparation"),  # ice phishing
           ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-SUSPICIOUS-TRANSFER", "Preparation"),  # ice phishing
           ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS", "Preparation"),  # ice phishing
           ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS", "Preparation"),  # ice phishing
           ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC20-APPROVAL-FOR-ALL", "Preparation"),  # ice phishing
           ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC721-APPROVAL-FOR-ALL", "Preparation"),  # ice phishing
           ("0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14", "ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL", "Preparation"),  # ice phishing
           ("0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", "FUNDING-TORNADO-CASH", "Funding"),  # tornado cash withdrawl
           ("0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a", "TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION", "Preparation"),  # Tornado Cash Funded Account Interaction
           ("0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2", "POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH", "MoneyLaundering"),  # money laundering
           ("0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4", "forta-text-messages-possible-hack", "MoneyLaundering"),  # forta-text-messages-agent
           ("0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5", "FLASHBOT-TRANSACTION", "Exploitation"),  # Flashbot
           ("0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3", "UNVERIFIED-CODE-CONTRACT-CREATION", "Preparation"),  # unverified contract creation
           ("0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895", "AE-MALICIOUS-ADDR", "Exploitation"),  # malicious address bot
           ("0x46ce98e921e2766a922840a56e89f24409001052c284e0bd6cbaa4fecd95e9b6", "SLEEPMINT-1", "Preparation"),  # sleep minting
           ("0x46ce98e921e2766a922840a56e89f24409001052c284e0bd6cbaa4fecd95e9b6", "SLEEPMINT-2", "Preparation"),  # sleep minting
           ("0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb", "CEX-FUNDING-1", "Funding"),  # CEX Funding
           ("0x47b86137077e18a093653990e80cb887be98e7445291d8cf811d3b2932a3c4d2", "AK-AZTEC-PROTOCOL-DEPOSIT-EVENT", "MoneyLaundering"),  # Aztec MoneyLaundering
           ("0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0", "UMBRA-RECEIVE", "Funding"),  # umbra receive
           ("0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46", "MALICIOUS-ACCOUNT-FUNDING", "Funding")  # Malicious Account Funding
        ]