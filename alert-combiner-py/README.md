# Alert Combiner

## Description

Individual alerts can have low precision (in other words raise false positives). This bot combines past alerts to separate the signal from noise. 

It does so with the realization that an attack usually consists of 4 distinct phases:
- funding (e.g. tornado cash funding)
- preparation (e.g. creation of an attacker contract)
- exploitation (e.g. draining funds from a contract)
- money laundering (e.g. sending funds to tornado cash)

As such, this detection bot combines previously raised alerts under the initiating address (i.e. the attacker address) for a given time window (2 calendar days, so between 24-48h) and emits a cricial alert when 
- alerts from all four phases have been observed 
- a certain combination of the first two stages (i.e. funding with tornado cash and attack simulation fired)
- a certain combination associated with ice phishing fired:
  - ice phishing & sleep minting 
  - ice phishing & TC interaction
  - ice phishing & (unverified contract & flashbot)
  - ice phishing & malicious address

The following bots are considered by the combiner and mapped to the stages in the following way:
| BotID | Name | AlertId | Stage |
|-------|------|---------|-------|
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-APPROVALS | Preparation |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-PREV-APPROVED-TRANSFERED | Exploitation |
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
| 0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127 | token impersonation | IMPERSONATED-TOKEN-DEPLOYMENT | Preparation |
| 0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5 | flashbot attack bot | FLASHBOT-TRANSACTION | Exploitation |
| 0x0f21668ebd017888e7ee7dd46e9119bdd2bc7f48dbabc375d96c9b415267534c | smart price change bot | SMART-PRICE-CHANGES | Preparation |
| 0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4 | text messages agent | forta-text-messages-possible-hack (high severity only) | MoneyLaundering |
| 0xfcf3ee41d04eee52f7944387010bc8aa6f22d54c36576c9a05db7e6cafda41f9 | balance decrease for bridge: polygon (ether) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xca504ee43501fe7c20084aa3112f8f57dd8c1e0e8a85d3884b66c252d6fc4f5b | balance decrease for bridge: polygon (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xa4b00d881c92526ef9a1db39cd3da2b7f32958eab2d7bb807546b7fd1a520748 | balance decrease for bridge: Avalanche - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x942c63db47285d28f01fba0a4e998f815f9784bf246fd981694fd1bcbc0e75c8 | balance decrease for bridge: Arbitrum (Ether Gateway) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x6f07249485378615abb12b352f7f0e9c68e6bab2de57475b963445e5639fced3 | balance decrease for bridge: Arbitrum (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x4db4efcb505c19e076f1716f9c79d919ffb6a9802769b470e8d461066730c723 | balance decrease for bridge: Arbitrum (Custom Gateway) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x3f5d0e780a99c3058b58884844e4c71df34b2b739fd957847facc77f69e9f2cc | balance decrease for bridge: Near/Aurora (Ether) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x59cc55fc71711d81d99be376618e072fa34e1ddbda7401840542d9a584a78d08 | balance decrease for bridge: Near/Aurora (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x94f879d399f7fe7a06682d3abd58a955624ec08b9164c3838851bf6788d27e33 | balance decrease for bridge: Optimism V1 - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x5474812f32fa8206c178864bb7f95f737ab9cdb1e4125af2e86ad8dd8c5fbf31 | balance decrease for bridge: Optimism V2 - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x966929e33d640fead63ed3307ee802e1a45a5b3fabe8c796acf1d6bceb2c757e | balance decrease for bridge: Harmony (Ether) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xb9008e67f9a2425dc0e11f80d8d26880ec83880b9a169c9542a8e8d74337bb44 | balance decrease for bridge: Harmony (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xee1a0da8184264ed000c2d33f0a6e0df3aa43ad515c21b8320a00aea8c3ae457 | balance decrease for bridge: Harmony (BUSD) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xe4cee68ce6b2d75ce17a2c727b92838a32e698eacb8848caaf6dade6f9330c12 | balance decrease for bridge: xDai - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xdac6f4a16776648ef48b0c9850800507059e201139c2aa898b47d51ca0ebdaae | balance decrease for bridge: Boba - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x742da1d837ac91905ec470d4e9d92e9c31a3104aa05a014a8f51ba355135bf8a | balance decrease for bridge: Ronin - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x7b69174f32b91731d9b6245faaff945637c47f729a850fa312a27238bc98f383 | balance decrease for bridge: THORChain - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xc10fe54aa93d43702eece2c439550ee079b5fa045aa03e08d47df6a3837e172b | balance decrease for bridge: Multichain/Anyswap (ALTA) - BSC | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xf947dfa6387710dd316cb9b1afec82d1f49d187426c8f6370000cddc2bec945d | balance decrease for bridge: Multichain/Anyswap (USDC) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x3d1242fb8af0cdd548e7b5e073534f298f7ddaebbafe931a3506ab0be0e67e87 | balance decrease for bridge: Multichain/Anyswap  (Marlin POND) - FTM | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x0b069cddde485c14666b35e13c0e0919e6bbb00ea7b0df711e45701b77841492 | balance decrease for bridge: Multichain/Anyswap (USDT) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x19f468cbd6924a77fcb375a130e3bd1d3764366e42d4d7e6db0717a2229bfeba | balance decrease for bridge: Multichain/Anyswap (USDT) - Polygon | 
| 0xfcf3ee41d04eee52f7944387010bc8aa6f22d54c36576c9a05db7e6cafda41f9 | balance decrease for bridge: polygon (ether) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xca504ee43501fe7c20084aa3112f8f57dd8c1e0e8a85d3884b66c252d6fc4f5b | balance decrease for bridge: polygon (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xa4b00d881c92526ef9a1db39cd3da2b7f32958eab2d7bb807546b7fd1a520748 | balance decrease for bridge: Avalanche - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x942c63db47285d28f01fba0a4e998f815f9784bf246fd981694fd1bcbc0e75c8 | balance decrease for bridge: Arbitrum (Ether Gateway) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x6f07249485378615abb12b352f7f0e9c68e6bab2de57475b963445e5639fced3 | balance decrease for bridge: Arbitrum (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x4db4efcb505c19e076f1716f9c79d919ffb6a9802769b470e8d461066730c723 | balance decrease for bridge: Arbitrum (Custom Gateway) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x3f5d0e780a99c3058b58884844e4c71df34b2b739fd957847facc77f69e9f2cc | balance decrease for bridge: Near/Aurora (Ether) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x59cc55fc71711d81d99be376618e072fa34e1ddbda7401840542d9a584a78d08 | balance decrease for bridge: Near/Aurora (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x94f879d399f7fe7a06682d3abd58a955624ec08b9164c3838851bf6788d27e33 | balance decrease for bridge: Optimism V1 - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x5474812f32fa8206c178864bb7f95f737ab9cdb1e4125af2e86ad8dd8c5fbf31 | balance decrease for bridge: Optimism V2 - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x966929e33d640fead63ed3307ee802e1a45a5b3fabe8c796acf1d6bceb2c757e | balance decrease for bridge: Harmony (Ether) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xb9008e67f9a2425dc0e11f80d8d26880ec83880b9a169c9542a8e8d74337bb44 | balance decrease for bridge: Harmony (ERC20) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xee1a0da8184264ed000c2d33f0a6e0df3aa43ad515c21b8320a00aea8c3ae457 | balance decrease for bridge: Harmony (BUSD) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xe4cee68ce6b2d75ce17a2c727b92838a32e698eacb8848caaf6dade6f9330c12 | balance decrease for bridge: xDai - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xdac6f4a16776648ef48b0c9850800507059e201139c2aa898b47d51ca0ebdaae | balance decrease for bridge: Boba - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x742da1d837ac91905ec470d4e9d92e9c31a3104aa05a014a8f51ba355135bf8a | balance decrease for bridge: Ronin - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x7b69174f32b91731d9b6245faaff945637c47f729a850fa312a27238bc98f383 | balance decrease for bridge: THORChain - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xc10fe54aa93d43702eece2c439550ee079b5fa045aa03e08d47df6a3837e172b | balance decrease for bridge: Multichain/Anyswap (ALTA) - BSC | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xf947dfa6387710dd316cb9b1afec82d1f49d187426c8f6370000cddc2bec945d | balance decrease for bridge: Multichain/Anyswap (USDC) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x3d1242fb8af0cdd548e7b5e073534f298f7ddaebbafe931a3506ab0be0e67e87 | balance decrease for bridge: Multichain/Anyswap  (Marlin POND) - FTM | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x0b069cddde485c14666b35e13c0e0919e6bbb00ea7b0df711e45701b77841492 | balance decrease for bridge: Multichain/Anyswap (USDT) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x19f468cbd6924a77fcb375a130e3bd1d3764366e42d4d7e6db0717a2229bfeba | balance decrease for bridge: Multichain/Anyswap (USDT) - Polygon |
| 0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabd3f9f6 | attack simulation - Ethereum Mainnet | AK-ATTACK-SIMULATION-0 | Preparation |
| 0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8 | Social Engineering Contract Creation Bot | SOCIAL-ENG-CONTRACT-CREATION | Preparation |
| 0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895 | Malicious Address Bot | AE-MALICIOUS-ADDR | Exploitation |
| 0x46ce98e921e2766a922840a56e89f24409001052c284e0bd6cbaa4fecd95e9b6 | Sleep Minting | SLEEPMINT-2, SLEEPMINT-1 | Preparation |
| 0xeab3b34f9c32e9a5cafb76fccbd98f98f441d9e0499d93c4b476ba754f8f0773 | Suspicious Contract Creation ML | SUSPICIOUS-CONTRACT-CREATION | Preparation | 
| 0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8 | Anomalous Token Transfers Detection Machine Learning Bot | ANOMALOUS-TOKEN-TRANSFERS-TX | Exploitation |
| 0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f | Assets Drained | FORTA-1 | Exploitation |
| 0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb | Large Native Token Transfers Out | LARGE-TRANSFER-OUT | Money Laundering |

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

- ALERT-COMBINER-2
  - Fired when alerts mapping to funding and preparation stages (attack simulation bot needs to fire) under one common EOA (the attacker address) have been observed
  - Severity is always set to "critical" 
  - Type is always set to "exploit" 
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the block number that will be reported as part of this alert may be unrelated to the alert, but represents more of a timestamp on when the attack was discovered.
  - Note: the detection bot will only alert once per EOA observed

- ALERT-COMBINER-ICE-PHISHING
  - Fired when alert combination is observed that points to an ice phishing attack
  - Severity is always set to "critical" 
  - Type is always set to "exploit" 
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the block number that will be reported as part of this alert may be unrelated to the alert, but represents more of a timestamp on when the attack was discovered.
  - Note: the detection bot will only alert once per EOA observed

## Test Data

The bot behaviour can be verified with the following blocks (assuming a default time window):

- Fei Rari - block number 14685062 (date range: April 29-30 2022) (only works on version 0.6 and prior)
