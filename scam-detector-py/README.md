# Scam Detector Bot

## Description

The Scam Detector bot combines past alerts under a common address from a variety of underlying base bots to emit a high precision label on EOAs and contract addresses. 

The Scam Detector bot has three handlers that process alerts differently:
1. Passthrough - this handler normalizes the alert information from the base bot and emits an label with minimal processing. 
2. ML - utilizes a supervised machine learning model taking number of specific alerts observed for a given EOA as input and predicts whether an EOA is a scammer
3. Propagation - this handler propagates labels from another label. E.g. a scammer was identified deployed an social engineering ice phishing contract. A similar contract bot identified a new scammer account deloying a similar contract. 

In addition, the scam detector can consume manual information from the Forta community to identify scammers. 

Which base bots are used by which handler is documented in the base bot table below.

## Supported Chains

- All Forta supported chains 

## Labels

The Scam Detector bot emits labels for identified scammer EOAs and contract addresses. The label will contain the following information:
- label/entity - the address (either EOA or contract address)
- label/entityType - EntityType.ADDRESS
- label/confidence - a confidence score from 0-1.0 with 1.0 being most confident the label is correct
- label/remove - a flag indicating whether the label is being added or removed
- label/label - a string denoting the label that was placed on the entity. It currently is set to 'scammer'
- label/metadata/bot_version - version of the bot when the label was added
- label/metadata/threat_category - (see below)
- label/metadata/address_type - EOA or contract
- label/metadata/logic - (passhthrough, ml, manual)
- label/metadata/threat_description_url - URL that describes the threat_category in more detail


Threat categories are as follows:
- sleep-minting - Fired when alert combination is observed that points to a sleep minting attack
- ice-phishing - Fired when alert combination is observed that points to an ice phishing attack
- wash-trading - Fired when a NFT wash trade has been observed
- fraudulent-nft-order - Fired when alert combination is observed that points to an fraudulent NFT order
- native-ice-phishing-social-engineering - Fired when alert combination is observed that points to an native ice phishing involving social engineering techniques (e.g. SecurityUpdate() function sig in the input data field)
- native-ice-phishing - Fired when alert combination is observed that points to an native ice phishing without social engineering component
- hard-rug-pull - Fired when a contract with hard rug pull techniques is identified
- soft-rug-pull - Fired when a contract with soft rug pull techniques is identified
- rake-token - Fired when a contract with a rake is identified
- impersonating-token - Fired when a token contract has been identified that is impersonating a known established token (e.g. USDC or USDT)
- address-poisoning - Fired when alert combination is observed that points to address poisoning attack; this threat category is used for labeling poisoning addresses
- address-poisoner - Fired when alert combination is observed that points to address poisoning attack; this threat category is used for labeling poisoner addresses, aka the address that is initiating the poisoning and the contract performing the poisioning
- private-key-compromise - Fired when it is suspected that a scammer (e.g. through malware) stolen someone's private key and started to drain assets from the user's wallet
- attack-stages - Fired when alert combination is observed that points to attack on chain that spans the 4 stages of an attack (funding, preparaiton, exploitation, and money laundering) Many of the alerts here point to rug pulls and rake tokens.
- similar contract - Fired when a similar contract to a previously identified scammer contract has been identified
- scammer association - Fired when an EOA is associated with a known scammer account (e.g. receiving or sending funds)
- scammer-deployed-contract - When a known scammer deploys a contract


Additional informaiton can be found on the label for provenance purposes:
- source/transactionHash - the hash of the transaction that the scam detector processed when emitting the label. Either source/transactionHash, source/block.numer or source/alertHash needs to be set.
- source/block.number - the number of the block that the scam detector processed when emitting the label. Either source/transactionHash, source/block.numer or source/alertHash needs to be set.
- source/alertHash - the hash of the alert that the scam detector processed when emitting the label. Either source/transactionHash, source/block.numer or source/alertHash needs to be set.
- base_bot_alert_ids - if one or more alerts were processed by the scam detector, this field contains the alert_ids of those alerts.
- base_bot_alert_hashes - if one or more alerts were processed by the scam detector, this field contains the alert_hashes of those alerts.
- deployer_info - if the label is a contract, this field provides additional information of the deployer.
- reported_by - if the label was manually emitted, this field provides information who reported the label.
- associated_scammer - an associated scammer comes into play for propagation alerts. This field contains the scammer entity from which the label was propagated from.
- associated_scammer_contract - an associated scammer comes into play for propagation alerts. If a contract was involved, this field contains the scammer contract address from which the label was propagated from.      
- associated_scammer_threat_categories - an associated scammer comes into play for propagation alerts. It contains all the threat categories associated with the original scammer.
- associated_scammer_threat_categories - an associated scammer comes into play for propagation alerts. It contains all alert_hashes with the original scammer.

In case of false positives are identified, the scam detector will emit a remove label.

Example label/label:
```
    'entityType': EntityType.Address,
    'label': "scammer",
    'entity': address,
    'confidence': 0.8,
    'remove': "false",
    'metadata': {
      'address_type=contract',
      'threat_category=ice_phishing',
      'logic=manual',
      'threat_description_url=https://forta.org/attack#ice-phishing'
    }
```

When a false positive is observed, the scam detector will remove the previously set label including removal of derived labels (e.g. a EOA deploying a contract; a similar contract being identified)
```
    'entityType': EntityType.Address,
    'label': "scammer",
    'entity': address,
    'confidence': 0.8,
    'remove': "true"
```

## Base Bots Utilized By Scam Detector

| BotID | Name | AlertId | Alert Logic |
|-------|------|---------|-------|
| 0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac | nft-phishing-sale | PassThrough |
| 0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac | nft-possible-phishing-transfer | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-APPROVALS | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-PREV-APPROVED-TRANSFERED | PassThrough |
| 0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400 | tornado cash withdrawl | FUNDING-TORNADO-CASH | Combination |
| 0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a | tornado cash funding | TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION | Combination |
| 0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2 | money laundering | POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH | Combination |
| 0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4 | txt messaging bot | forta-text-messages-possible-hack | Combination |
| 0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3 | unverified contract creation | UNVERIFIED-CODE-CONTRACT-CREATION | Combination |
| 0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5 | flashbot attack bot | FLASHBOT-TRANSACTION | Combination |
| 0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4 | text messages agent | forta-text-messages-possible-hack (high severity only) | Combination |
| 0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895 | Malicious Address Bot | AE-MALICIOUS-ADDR | Combination |
| 0x46ce98e921e2766a922840a56e89f24409001052c284e0bd6cbaa4fecd95e9b6 | Sleep Minting | SLEEPMINT-2, SLEEPMINT-1 | Combination |
| 0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef | Aztec funded contract interaction | AK-AZTEC-PROTOCOL-FUNDED-ACCOUNT-INTERACTION-0 | Combination |
| 0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb | CEX Funding bot | CEX-FUNDING-1 | Combination |
| 0x9fbf4db19f23627633d86bb1936dabad0b27ebe09b7a38028a126392156f7f32 | Aztec Funding bot | AK-AZTEC-PROTOCOL-FUNDING | Combination |
| 0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46 | Malicious Account Funding Bot | MALICIOUS-ACCOUNT-FUNDING | Combination |
| 0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0 | Umbra bot | UMBRA-RECEIVE | Combination |
| 0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e | ChangeNow Funding | FUNDING-CHANGENOW-NEW-ACCOUNT | Combination |
| 0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad | Malicious Token ML | SUSPICIOUS-TOKEN-CONTRACT-CREATION | Combination |
| 0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799 | Attack Detector V3 | ATTACK-DETECTOR-1 | PassThrough |
| 0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502 | Address Poisoning Bot | ADDRESS-POISONING | PassThrough |
| 0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502 | Address Poisoning Bot | ADDRESS-POISONING-LOW-VALUE | PassThrough |
| 0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502 | Address Poisoning Bot | ADDRESS-POISONING-FAKE-TOKEN | PassThrough |
| 0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0 | Native Ice Phishing Bot | NIP-1 | PassThrough |
| 0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0 | Native Ice Phishing Bot | NIP-4 | PassThrough |
| 0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0 | Native Ice Phishing Bot | NIP-5 | PassThrough |
| 0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0 | Native Ice Phishing Bot | NIP-6 | PassThrough |
| 0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732 | Wash trading bot | NFT-WASH-TRADE | PassThrough | 
| 0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560 | contract similarity bot | NEW-SCAMMER-CONTRACT-CODE-HASH | PassThrough |
| 0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15 | hard rug pull bot | HARD-RUG-PULL-1 | PassThrough |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull bot | SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION | PassThrough |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull bot | SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE | PassThrough |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull bot | SOFT-RUG-PULL-SUS-POOL-REMOVAL && SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE | PassThrough |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull bot | SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE && SOFT-RUG-PULL-SUS-POOL-REMOVAL | PassThrough |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull bot | SOFT-RUG-PULL-SUS-POOL-REMOVAL && SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION | PassThrough |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull bot | SOFT-RUG-PULL-SUS-POOL-REMOVAL | PassThrough |
| 0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11 | rake token bot | RAKE-TOKEN-CONTRACT-1 | PassThrough |
| 0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848 | scammer association bot | SCAMMER-LABEL-PROPAGATION-1 | PassThrough |
| 0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127 | token impersonation | IMPERSONATED-TOKEN-DEPLOYMENT-POPULAR | PassThrough |
| 0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac | nft trader | nft-possible-phishing-transfer | PassThrough |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS | PassThrough |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-PERMITTED-ERC20-TRANSFER | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-SUSPICIOUS-TRANSFER | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-ERC721-APPROVALS | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC20-APPROVAL-FOR-ALL | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC721-APPROVAL-FOR-ALL | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC20-SCAM-PERMIT | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC20-SCAM-CREATOR-PERMIT | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-SCAM-APPROVAL | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-SCAM-CREATOR-APPROVAL | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-SCAM-TRANSFER | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-SCAM-CREATOR-TRANSFER | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-PULL-SWEEPTOKEN | Passthrough |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-OPENSEA-PROXY-UPGRADE | Passthrough |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-PIG-BUTCHERING | Passthrough |
| 0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba | sleep minting | SLEEPMINT-3 | Combination |
| 0x47b86137077e18a093653990e80cb887be98e7445291d8cf811d3b2932a3c4d2 | aztec bot | AK-AZTEC-PROTOCOL-DEPOSIT-EVENT | Combination |
| 0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848 | scammer label propagation | SCAMMER-LABEL-PROPAGATION-2 | PassThrough |
| 0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058 | funding laundering bot | FLD_FUNDING | Combination |
| 0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058 | funding laundering bot | FLD_Laundering | Combination |
| 0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058 | funding laundering bot | FLD_NEW_FUNDING | Combination |
| 0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0 | native ice phishing | NIP-2 | Combination |
| 0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8 | anomalous token ML model | ANOMALOUS-TOKEN-TRANSFERS-TX | Combination |
| 0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8 | anomalous token ML model | INVALID-TOKEN-TRANSFERS-TX | Combination |
| 0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8 | anomalous token ML model | NORMAL-TOKEN-TRANSFERS-TX | Combination |
| 0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba | sleep minting | SLEEPMINT-1 | Combination |
| 0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99 | suspicious contract creation | SUSPICIOUS-CONTRACT-CREATION | Combination |
| 0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99 | suspicious contract creation | SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH | Combination |
| 0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac | nft trader | indexed-nft-sale | Combination |
| 0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac | nft trader | nft-sale | Combination |
| 0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac | nft trader | nft-sold-above-floor-price | Combination |
| 0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac | nft trader | scammer-nft-trader | Combination |
| 0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127 | impersonating token bot | IMPERSONATED-TOKEN-DEPLOYMENT | Combination |
| 0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac | large profit bot | LARGE-PROFIT | Combination |
| 0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad | malicious token contract ML bot | NON-MALICIOUS-TOKEN-CONTRACT-CREATION | Combination |
| 0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad | malicious token contract ML bot | SAFE-TOKEN-CONTRACT-CREATION | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-APPROVAL-FOR-ALL | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC20-PERMIT | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC20-PERMIT-INFO | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO | Combination |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-SUSPICIOUS-APPROVAL | Combination |
| 0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e | change now bot | FUNDING-CHANGENOW-LOW-AMOUNT | Combination |
| 0x98b87a29ecb6c8c0f8e6ea83598817ec91e01c15d379f03c7ff781fd1141e502 | address poisoning bot | ADDRESS-POISONING-ZERO-VALUE | Combination |
| 0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c | contract ML bot | SAFE-CONTRACT-CREATION | Combination |
| 0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c | contract ML bot | SUSPICIOUS-CONTRACT-CREATION | Combination |
| 0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b | MEV bot | MEV-ACCOUNT | Combination |
| 0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb | large transfer out bot | LARGE-TRANSFER-OUT | Combination |
| 0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5 | flashbot bot | FLASHBOTS-TRANSACTIONS | Combination |
| 0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15 | hard rug pull | HARD-RUG-PULL-HONEYPOT-DYNAMIC | Combination |
| 0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f | positive reputation bot | POSITIVE-REPUTATION-1 | Combination |
| 0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f | asset drained bot | ASSET-DRAINED | Combination |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull | SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION | Combination |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull | SOFT-RUG-PULL-SUS-LIQ-POOL-RESERVE-CHANGE | Combination |
| 0xf234f56095ba6c4c4782045f6d8e95d22da360bdc41b75c0549e2713a93231a4 | soft rug pull | SOFT-RUG-PULL-SUS-LIQ-POOL-CREATION && SOFT-RUG-PULL-SUS-POOL-REMOVAL | PassThrough |
| 0x6ec42b92a54db0e533575e4ebda287b7d8ad628b14a2268398fd4b794074ea03 | private key compromise | PKC-2 | PassThrough |

