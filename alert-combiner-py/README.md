# Alert Combiner

## Description

Individual alerts can have low precision (in other words raise false positives). This bot combines past alerts to separate the signal from noise. 

It does so with the realization that an attack usually consists of 4 distinct phases:
- funding (e.g. tornado cash funding)
- preparation (e.g. creation of an attacker contract)
- exploitation (e.g. draining funds from a contract)
- money laundering (e.g. sending funds to tornado cash)

As such, this detection bot combines previously raised alerts under the initiating address (i.e. the attacker address) for a given time window (2 calendar days, so between 24-48h) and emits a cricial alert when alerts from all four phases have been observed. 

The following bots are considered by the combiner and mapped to the stages in the following way:
| BotID | Name | AlertId | Stage |
|-------|------|---------|-------|
| 0xd9fe61cfe875470b80318a96cc0a94ba3adbe1eb4a14827fa018f14925e7da64 | ice phishing | ICE-PHISHING-HIGH-NUM-APPROVALS | Preparation |
| 0xd9fe61cfe875470b80318a96cc0a94ba3adbe1eb4a14827fa018f14925e7da64 | ice phishing | ICE-PHISHING-PREV-APPROVED-TRANSFERED | Exploitation |
| 0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99 | suspicious contract creation | SUSPICIOUS-CONTRACT-CREATION | Preparation |
| 0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99 | suspicious contract creation | SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH | Preparation |
| 0xaedda4252616d971d570464a3ae4a9f0a9d72a57d8581945fff648d03cd30a7d | blocklisted account tx | FORTA-BLOCKLIST-ADDR-TX | Preparation |
| 0x4cc272e78a685e27abcccdb40578f91f43baecc43e3c465460991a9dcdcb9756 | tornado cash withdrawl | AE-FORTA-0 | Funding |
| 0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a | tornado cash funding | TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION | Funding |
| 0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9 | reentrancy | NETHFORTA-25 | Exploitation |
| 0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2 | money laundering | POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH | MoneyLaundering |
| 0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7 | high gas usage | IMPOSSIBLE-2 | Exploitation |
| 0xe27867c40008e0e3533d6dba7d3c1f26a61a3923bc016747d131f868f8f34555 | high gas price | FORTA-2 | Exploitation |
| 0xbf953b115fd214e1eb5c4d6f556ea30f0df47bd86bf35ce1fdaeff03dc7df5b7 | high value transaction | NETHFORTA-2 | Exploitation |
| 0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4 | txt messaging bot | forta-text-messages-possible-hack | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot | SUCCESSFUL-INTERNAL-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot |  SUCCESSFUL-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot | FAILED-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot | FAILED-INTERNAL-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x55636f5577694c83b84b0687eb77863850c50bd9f6072686c8463a0cbc5566e0 | flashloan detector | FLASHLOAN-ATTACK | Exploitation |
| 0x2c8452ff81b4fa918a8df4441ead5fedd1d4302d7e43226f79cb812ea4962ece | Large Mint Borrow Volume Anomaly Detection | HIGH-BORROW-VALUE | Exploitation |
| 0x2c8452ff81b4fa918a8df4441ead5fedd1d4302d7e43226f79cb812ea4962ece | Large Mint Borrow Volume Anomaly Detection | HIGH-MINT-VALUE | Exploitation |
| 0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3 | unverified contract creation | UNVERIFIED-CODE-CONTRACT-CREATION | Preparation |



As a result, the precision of this alert is quite high, but also some attacks may be missed. Note, in the case where attacks are missed, the broader set of detection bots deployed on Forta will still raise individual alerts that users can subscribe to.

## Supported Chains

- All Forta supported chains (note, it will appear that the bot only executes on one chain, but as it queries past Forta alerts, it essentially covers all chains)

## Alerts

Describe each of the type of alerts fired by this bot

- ALERT-COMBINER-1
  - Fired when alerts mapping to all 4 stages under one common EOA (the attacker address) have been observed
  - Severity is always set to "critical" 
  - Type is always set to "exploit" 
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the block number that will be reported as part of this alert may be unrelated to the alert, but represents more of a timestamp on when the attack was discovered.
  - Note: the detection bot will only alert once per EOA observed

## Test Data

The bot behaviour can be verified with the following blocks (assuming a default time window):

- Fei Rari - block number 14685062 (date range: April 29-30 2022) (only works on version 0.6 and prior)
