# Scam Detector Bot

## Description

The Scam Detector bot combines past alerts under a common address from a variety of underlying base bots to emit a high precision alert. It does so by mapping each alert to the four attack stages (Funding, Preparation, Exploitaiton and Money Laundering/ Post Exploitation) utilizing a heuristic detection approach.

Individual alerts can have low precision (in other words raise false positives). This feed combines past alerts to separate the signal from noise. 

It does so with the realization that an attack usually consists of 4 distinct phases:
- funding (e.g. tornado cash funding)
- preparation (e.g. creation of an attacker contract)
- exploitation (e.g. draining funds from a contract)
- money laundering (e.g. sending funds to tornado cash)/ post exploitation (e.g. on-chain txt messages)

As such, this feed combines previously raised alerts under the initiating address (i.e. the scammer address) for a given time window (2 calendar days, so between 24-48h) and emits a cricial alert when a specific combination of alerts is observed. 

As a result, the precision of this alert is quite high, but also some scams may be missed. Note, in the case where scams are missed, the broader set of detection bots deployed on Forta will still raise individual alerts that users can subscribe to.

## Supported Chains

- All Forta supported chains (note, it will appear that the bot only executes on one chain, but as it queries past Forta alerts, it essentially covers all chains)

## Alerts

The Scam Detector bot emits the following alerts:

- SCAM-DETECTOR-ICE-PHISHING
  - Fired when alert combination is observed that points to an ice phishing attack

- SCAM-DETECTOR-WASH-TRADE
  - Fired when a NFT wash trade has been observed

- SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER
  - Fired when alert combination is observed that points to an fraudulent seaport order

- SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING
  - Fired when alert combination is observed that points to an native ice phishing involving social engineering techniques (e.g. SecurityUpdate() function sig in the input data field)

- SCAM-DETECTOR-ADDRESS-POISONING
  - Fired when alert combination is observed that points to address poisoning attack

- SCAM-DETECTOR-1
- Fired when alert combination is observed that points to attack on chain that spans the 4 stages of an attack (funding, preparaiton, exploitation, and money laundering) Many of the alerts here point to rug pulls and rake tokens.

The properties for the alerts above are identical:
- Severity is always set to "critical" 
- Type is always set to "exploit" 
- Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - attacker_address: string
  - start_date: date str (%Y-%m-%d)
  - end_date: date str (%Y-%m-%d)
  - involved_addresses_x: string
  - involved_alert_id_x: string
  - involved_alert_hashes_x: string

In addition, this bot also emits an alert in case a false positive has been observed. 

- SCAM-DETECTOR-ICE-PHISHING-FALSE-POSITIVE
  - Fired when an FP has been identified
  - Severity is always set to "info" 
  - Type is always set to "info" 


The Scam Detector bot emits labels for each scammer address observed. The meta data contains the corresponding alertID. E.g.
```
    'entityType': EntityType.Address,
    'label': "scam",
    'entity': address,
    'confidence': 0.8,
    'remove': "false",
    'metadata': {
      'alert_id': alert_id,
      'chain_id': chain_id
    }
```

When a false positive is observed, the scam detector will remove the previously set label:
```
    'entityType': EntityType.Address,
    'label': "scam",
    'entity': address,
    'confidence': 0.8,
    'remove': "true"
```

## Base Bots Utilized By Scam Detector

| BotID | Name | AlertId | Stage |
|-------|------|---------|-------|
| 0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c | SEAPORT-PHISHING-TRANSFER | Exploitation |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-APPROVALS | Preparation |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-PREV-APPROVED-TRANSFERED | Exploitation |
| 0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400 | tornado cash withdrawl | FUNDING-TORNADO-CASH | Funding |
| 0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a | tornado cash funding | TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION | Funding |
| 0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2 | money laundering | POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH | MoneyLaundering |
| 0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4 | txt messaging bot | forta-text-messages-possible-hack | Exploitation |
| 0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3 | unverified contract creation | UNVERIFIED-CODE-CONTRACT-CREATION | Preparation |
| 0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5 | flashbot attack bot | FLASHBOT-TRANSACTION | Exploitation |
| 0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4 | text messages agent | forta-text-messages-possible-hack (high severity only) | MoneyLaundering |
| 0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895 | Malicious Address Bot | AE-MALICIOUS-ADDR | Exploitation |
| 0x46ce98e921e2766a922840a56e89f24409001052c284e0bd6cbaa4fecd95e9b6 | Sleep Minting | SLEEPMINT-2, SLEEPMINT-1 | Preparation |
| 0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef | Aztec funded contract interaction | AK-AZTEC-PROTOCOL-FUNDED-ACCOUNT-INTERACTION-0 | Exploitation |
| 0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb | CEX Funding bot | CEX-FUNDING-1 | Funding |
| 0x9fbf4db19f23627633d86bb1936dabad0b27ebe09b7a38028a126392156f7f32 | Aztec Funding bot | AK-AZTEC-PROTOCOL-FUNDING | Funding |
| 0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46 | Malicious Account Funding Bot | MALICIOUS-ACCOUNT-FUNDING | Funding |
| 0xdba64bc69511d102162914ef52441275e651f817e297276966be16aeffe013b0 | Umbra bot | UMBRA-RECEIVE | Funding |
| 0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e | ChangeNow Funding | FUNDING-CHANGENOW-NEW-ACCOUNT | Funding |
| 0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad | Malicious Token ML | SUSPICIOUS-TOKEN-CONTRACT-CREATION | Preparation |
| 0x067e4c4f771f288c686efa574b685b98a92918f038a478b82c9ac5b5b6472732 | Wash trading bot | NFT-WASH-TRADE | Preparation | 