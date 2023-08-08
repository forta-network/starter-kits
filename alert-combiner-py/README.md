# Attack Detector Feed

## Description

The Attack Detector bot combines past alerts under a common address from a variety of underlying base bots to emit a high precision alert. It does so by mapping each alert to the four attack stages (Funding, Preparation, Exploitaiton and Money Laundering/ Post Exploitation) utilizing an anomaly as well as heuristic detection approach.

Individual alerts can have low precision (in other words raise false positives). This bot combines past alerts from base bots to separate the signal from noise.

It does so with the realization that an attack usually consists of 4 distinct phases:

- funding (e.g. tornado cash funding)
- preparation (e.g. creation of an attacker contract)
- exploitation (e.g. draining funds from a contract)
- money laundering (e.g. sending funds to tornado cash)/ post exploitation (e.g. on-chain txt messages)

As such, this feed combines previously raised alerts under the initiating address (i.e. the attacker address/ addresses) and emits a cricial alert when:

1. Anomaly Detection Appoach

   1. Alert Criteria

   - each alert emits an anomaly score
   - anomaly score from each base bot is mapped to an attack stage
   - the minimum anomaly scores per attack stage are combined (multiplied) across all stages for a common cluster (a set of addresses clustered by the cluster entity bot)
   - thresholds on the number of total alerts (3) and anomaly score (threshold of 1 _ 10-7 for critical, 1 _ 10-4 for low severity alerts)
   - is not part of a FP mitigation alert
   - is not part of an end user attack alert

   2. Example

   - ICE-PHISHING-HIGH-NUM-APPROVALS with an anomaly score of 0.0001 and an attack stage mapping of Preparation
   - ICE-PHISHING-PREV-APPROVED-TRANSFERED with an anomaly score of 0.0005 and an attack stage mapping of Exploitation
   - SUSPICIOUS-CONTRACT-CREATION with an anomaly score of 0.01 and an attack stage mapping of Preparation

   3. Result

   - The overall anomaly score would be min_preparation_anomaly_score(0.0001, 0.01) * min_exploitation_anomaly_score(0.0005) results in an overall anomaly score of 5*10-8. Since 3 alerts were raised in total, the Attack Detector would emit a critical ATTACK-DETECTOR-3 alert.

2. Heuristic Approach utilizing highly precise alert from a subset of the base bots (currently the ML contract model bot and the attack simulation bot)

   1. Alert Criteria

   - a highly precise alert is emitted plus one more additional alert from different stage or 1 more alerts from different highly precise bots is emitted for a common cluster (a set of addresses clustered by the cluster entity bot)
   - is not part of a FP mitigation alert
   - is not part of an end user attack alert

   2. Example

   - AK-ATTACK-SIMULATION-0 (this is a highly precise alert)
   - CEX-FUNDING-1

   3. Result

   - The anomaly score is not relevant, but rather a heurstic would cause the bot to trigger a critical ATTACK-DETECTOR-2 alert.

3. Heuristic Approach utilizing the alert to attack stage mapping
   1. Alert Criteria
   - an alert is emitted in each of the 4 attack stages for a common cluster (a set of addresses clustered by the cluster entity bot)
   - is not part of a FP mitigation alert
   - is not part of an end user attack alert
   2. Example
   - CEX-FUNDING-1 (Funding)
   - SUSPICIOUS-CONTRACT-CREATION (Preparation)
   - FLASHBOT-TRANSACTION (Exploitation)
   - POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH (Money Laundering)
   3. Result
   - The anomaly score is not relevant, but rather a heurstic would cause the bot to trigger a critical ATTACK-DETECTOR-1 alert.

As a result, the precision of this alert is quite high, but also some attacks may be missed. Note, in the case where attacks are missed, the broader set of detection bots deployed on Forta will still raise individual alerts that users can subscribe to.

## Supported Chains

- All EVM compatible chains

## Alerts

The Attack Detector bot emits the following alerts:

- ATTACK-DETECTOR-1

  - Fired when 4 alerts in each stages fire (this is consistent with attack detector V1 behavior)
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the detection bot will only alert once per cluster observed

- ATTACK-DETECTOR-2

  - Fired when 2 alerts in each stage fire, but do involve a highly precice bot (e.g. contract ML model or attack simulation)
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the detection bot will only alert once per cluster observed

- ATTACK-DETECTOR-3

  - Fired when 3 alerts are fired and anomaly score across the stages (per cluster) exceed the strict threshold (1 \* 10-7)
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the detection bot will only alert once per cluster observed

- ATTACK-DETECTOR-4

  - Fired when 3 alerts are fired and anomaly score across the stages (per cluster) exceed the loose threshold 1 \* 10-4). This alert is only emitted in beta version of bot.
  - Severity is always set to "low"
  - Type is always set to "exploit"
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the detection bot will only alert once per cluster observed

- ATTACK-DETECTOR-5

  - Fires when any of the above alerts would have triggered, but was FP mitigated. This alert is only emitted in beta version of bot.
  - Severity is always set to "info"
  - Type is always set to "exploit"
  - Note: the detection bot will only alert once per cluster observed

- ATTACK-DETECTOR-6
  - Fires when any of the above alerts would have triggered, but was associated with an end user attack. This alert is only emitted in beta version of bot.
  - Severity is always set to "info"
  - Type is always set to "exploit"
  - Note: the detection bot will only alert once per cluster observed

## Labels

The Attack Detector bot emits labels for each attacker address observed. The meta data contains the corresponding alertID. E.g.

```
    'entityType': EntityType.Address,
    'label': "attacker",
    'entity': address,
    'confidence': 0.99,
    'remove': "false",
    'metadata': {
      'alert_id': alert_id,
      'chain_id': chain_id
    }
```

## Base Bots Utilized By Attack Detector

The following bots are considered by the Attack Detector bot and mapped to the stages in the following way:
| BotID | Name | AlertId | Stage |
|-------|------|---------|-------|
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-HIGH-NUM-APPROVALS | Preparation |
| 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14 | ice phishing | ICE-PHISHING-PREV-APPROVED-TRANSFERED | Exploitation |
| 0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99 | suspicious contract creation | SUSPICIOUS-CONTRACT-CREATION | Preparation |
| 0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99 | suspicious contract creation | SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH | Preparation |
| 0x0e82982faa7878af3fad8ddf5042762a3b78d8949da2e301f1adfedc973f25ea | blocklisted account tx | EXPLOITER-ADDR-TX | Preparation |
| 0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400 | tornado cash withdrawl | FUNDING-TORNADO-CASH | Funding |
| 0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a | tornado cash funding | TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION | Funding |
| 0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9 | reentrancy | NETHFORTA-25 | Exploitation |
| 0x4adff9a0ed29396d51ef3b16297070347aab25575f04a4e2bd62ec43ca4508d2 | money laundering | POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH | MoneyLaundering |
| 0x7e1a8db7fec345b3e735b97b2ba61e74e1cc308c5effda9bd646debffbed2d14 | high gas usage | NETHFORTA-1 | Exploitation |
| 0xe27867c40008e0e3533d6dba7d3c1f26a61a3923bc016747d131f868f8f34555 | high gas price | FORTA-2 | Exploitation |
| 0xbf953b115fd214e1eb5c4d6f556ea30f0df47bd86bf35ce1fdaeff03dc7df5b7 | high value transaction | NETHFORTA-2 | Exploitation |
| 0x11b3d9ffb13a72b776e1aed26616714d879c481d7a463020506d1fb5f33ec1d4 | txt messaging bot | forta-text-messages-possible-hack | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot | SUCCESSFUL-INTERNAL-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot | SUCCESSFUL-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot | FAILED-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x20d57d727a2d7bf4b447d1952d7ea44efeda0920e45e779d298d5385f3b36cfa | tx volume anomaly bot | FAILED-INTERNAL-TRANSACTION-VOL-INCREASE | Exploitation |
| 0x55636f5577694c83b84b0687eb77863850c50bd9f6072686c8463a0cbc5566e0 | flashloan detector | FLASHLOAN-ATTACK, FLASHLOAN-ATTACK-WITH-HIGH-PROFIT | Exploitation |
| 0x2c8452ff81b4fa918a8df4441ead5fedd1d4302d7e43226f79cb812ea4962ece | Large Mint Borrow Volume Anomaly Detection | HIGH-BORROW-VALUE | Exploitation |
| 0x2c8452ff81b4fa918a8df4441ead5fedd1d4302d7e43226f79cb812ea4962ece | Large Mint Borrow Volume Anomaly Detection | HIGH-MINT-VALUE | Exploitation |
| 0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3 | unverified contract creation | UNVERIFIED-CODE-CONTRACT-CREATION | Preparation |
| 0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127 | token impersonation | IMPERSONATED-TOKEN-DEPLOYMENT | Preparation |
| 0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5 | flashbot attack bot | FLASHBOTS-TRANSACTIONS | Exploitation |
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
| 0x3d1242fb8af0cdd548e7b5e073534f298f7ddaebbafe931a3506ab0be0e67e87 | balance decrease for bridge: Multichain/Anyswap (Marlin POND) - FTM | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x0b069cddde485c14666b35e13c0e0919e6bbb00ea7b0df711e45701b77841492 | balance decrease for bridge: Multichain/Anyswap (USDT) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x19f468cbd6924a77fcb375a130e3bd1d3764366e42d4d7e6db0717a2229bfeba | balance decrease for bridge: Multichain/Anyswap (USDT) - Polygon | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xfbf1919aa876648dfe82315e529f1e7a98103a0b9ae38750e5e53b86fc80bd96 | balance decrease for bridge: Polygon zkEVM Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xd2520a2b0f6dbbf815ba33376f36a406393508e709d8f50e13d4ebad43490a59 | balance decrease for bridge: Across Ethereum SpokePool - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x5ab3964d3cb90ad68b6f307a7d5d3219b97c89c74e6aca261633af356ff73b4a | balance decrease for bridge: Celer Network Original Token Vault V2 - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x80749e2072849dacecaea54ec4d4b06d8da4e8c48ebf4cfe8fe9aeb0436a5776 | balance decrease for bridge: Celer Network Original Token Vault 2 - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xd40554c0cc8393cb94aa22f4e10d67672a76f64112577f2d700b13bb08405926 | balance decrease for bridge: Celer Network cBridge V2 Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x6639e223026aaec3c2c2e33c3a501f34e7a63e3c16d301f4f1ba0044135387e8 | balance decrease for bridge: Hop Protocol SNX Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x50679441079cf1f109311b5559c8141b30001cca0b0cee7e12067b1b4a5cf595 | balance decrease for bridge: Hop Protocol Matic Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x2cb9c3b887edada37b9f198fdd84d12cfc5eeb81d4ea365e5e0097ba829ee2d9 | balance decrease for bridge: Hop Protocol ERC20 Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xf8ca51a34b1d14819a01b731264d0b3356a186d7e42abb3b24eebd6848959823 | balance decrease for bridge: Hop Protocol DAI Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xa8dfec4641f94e2682aacec00bf2b136053d1298f3aa9324213b01f48b3a013c | balance decrease for bridge: Hop Protocol USDC Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xdd72bddaeecbd1b4022c9275538fc4cb268b16980ad06428d697a36c1b61e208 | balance decrease for bridge: Hop Protocol USDT Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x22673b42f62e43091c68378aa78f24a771f4f79042e2fb10eaedf53b1e07a75c | balance decrease for bridge: Hop Protocol Ethereum Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xc9887704aa0f002227b1461005d829e73095bc0263c31c631278780455ec8579 | balance decrease for bridge: Multichain anyUSDT Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x964cbcb16f9d3e1152a1b62638961fc4ec50fa4dddb253b48685ae3ae6cd175e | balance decrease for bridge: Multichain Fantom Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x469d0e38ab07a111f951795c4507028d3ddd2f5bf40076c221a6cc3f0c8df2d4 | balance decrease for bridge: Multichain anyETH Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xd1e0a1991031894f79845fdb21cf36d80e5c35a11761d1b9acddc111ab3b3ab6 | balance decrease for bridge: Polygon Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x7c67654fca8537473b9cebfa779885204cad216d4403d8cd93239cd2223b7e6d | balance decrease for bridge: Arbitrum DAI L1 Escrow - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x0b5f51563d1ca3fb74a17af67db998cbc290fce19f1db716e7cc7cbfa1b2a9fc | balance decrease for bridge: Arbitrum Outbox - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x61b3d0c3987c7d10de55711acd8e4f9892db924373a9d879605a5732ddde80c3 | balance decrease for bridge: Arbitrum Delayed Inbox - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xf193941c3ca27034453cdded1c270495fdd1319e71e026c44980ad35e52bf3f2 | balance decrease for bridge: Lido Optimism L1 ERC20 Token Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x5514223d7d7bf9b1ec1eb5981eb471cb8eb7756fc615ca282de9a157b126694f | balance decrease for bridge: Wormhole Portal Token Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x98573cc633608a04c4a2aa963f58eaa5106fe20bbec33cd88fafeb5db293f2c0 | balance decrease for bridge: Near Rainbow Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x259952782ab7cb9ca42068dde334da5b2d49bf40963f63b3ae97ab25bfbb1046 | balance decrease for bridge: Stargate STG Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x4e94072946966e73c7333042f9285d7a88cced482241873a476d2de37b3faead | balance decrease for bridge: Stargate FRAX Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x7992c56564a94597eb3f952e0a603af471935c61d912f8ebf88f95f722df2df2 | balance decrease for bridge: Stargate ETH Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x19af004c822158e573668cf0bb39a2494faf471135676b08ab981327c44daf35 | balance decrease for bridge: Stargate SUSDT Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xf75e0714bd3a4f1df970c6d069ab3b457a2593846becef948751097d18d3286d | balance decrease for bridge: Stargate SUSDC Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xbc1f5127113aeb6332451d5a5e51bf0bdd707c45eca26083e312c2066819a739 | balance decrease for bridge: Symbiosis Finance Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x8c11dd81c639757b97f17de27a67d9b07bcd6c33f4b23ba94339728db460f03a | balance decrease for bridge: Synapse Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x67955dd1f25ab38cc5065d62453e73f77b8de43a79ad745c5f3816906c8fe815 | balance decrease for bridge: Gnosis xDai-ETH Omni Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0x639c7768c5c28a1623aa0748aa5aa8c07be20542803820a2186179ac9715ff73 | balance decrease for bridge: zkSync Era Diamond Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
| 0xd2f60f7626eaeb15c4026578e28f799afb1587db3a8e4cb5bf2d42b54e13933d | balance decrease for bridge: zkSync Era Bridge - Ethereum | BALANCE-DECREASE-ASSETS-ALL-REMOVED | Exploitation |
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
| 0x3d1242fb8af0cdd548e7b5e073534f298f7ddaebbafe931a3506ab0be0e67e87 | balance decrease for bridge: Multichain/Anyswap (Marlin POND) - FTM | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x0b069cddde485c14666b35e13c0e0919e6bbb00ea7b0df711e45701b77841492 | balance decrease for bridge: Multichain/Anyswap (USDT) - Ethereum Mainnet | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x19f468cbd6924a77fcb375a130e3bd1d3764366e42d4d7e6db0717a2229bfeba | balance decrease for bridge: Multichain/Anyswap (USDT) - Polygon | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xfbf1919aa876648dfe82315e529f1e7a98103a0b9ae38750e5e53b86fc80bd96 | balance decrease for bridge: Polygon zkEVM Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xd2520a2b0f6dbbf815ba33376f36a406393508e709d8f50e13d4ebad43490a59 | balance decrease for bridge: Across Ethereum SpokePool - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x5ab3964d3cb90ad68b6f307a7d5d3219b97c89c74e6aca261633af356ff73b4a | balance decrease for bridge: Celer Network Original Token Vault V2 - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x80749e2072849dacecaea54ec4d4b06d8da4e8c48ebf4cfe8fe9aeb0436a5776 | balance decrease for bridge: Celer Network Original Token Vault 2 - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xd40554c0cc8393cb94aa22f4e10d67672a76f64112577f2d700b13bb08405926 | balance decrease for bridge: Celer Network cBridge V2 Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x6639e223026aaec3c2c2e33c3a501f34e7a63e3c16d301f4f1ba0044135387e8 | balance decrease for bridge: Hop Protocol SNX Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x50679441079cf1f109311b5559c8141b30001cca0b0cee7e12067b1b4a5cf595 | balance decrease for bridge: Hop Protocol Matic Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x2cb9c3b887edada37b9f198fdd84d12cfc5eeb81d4ea365e5e0097ba829ee2d9 | balance decrease for bridge: Hop Protocol ERC20 Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xf8ca51a34b1d14819a01b731264d0b3356a186d7e42abb3b24eebd6848959823 | balance decrease for bridge: Hop Protocol DAI Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xa8dfec4641f94e2682aacec00bf2b136053d1298f3aa9324213b01f48b3a013c | balance decrease for bridge: Hop Protocol USDC Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xdd72bddaeecbd1b4022c9275538fc4cb268b16980ad06428d697a36c1b61e208 | balance decrease for bridge: Hop Protocol USDT Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x22673b42f62e43091c68378aa78f24a771f4f79042e2fb10eaedf53b1e07a75c | balance decrease for bridge: Hop Protocol Ethereum Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xc9887704aa0f002227b1461005d829e73095bc0263c31c631278780455ec8579 | balance decrease for bridge: Multichain anyUSDT Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x964cbcb16f9d3e1152a1b62638961fc4ec50fa4dddb253b48685ae3ae6cd175e | balance decrease for bridge: Multichain Fantom Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x469d0e38ab07a111f951795c4507028d3ddd2f5bf40076c221a6cc3f0c8df2d4 | balance decrease for bridge: Multichain anyETH Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xd1e0a1991031894f79845fdb21cf36d80e5c35a11761d1b9acddc111ab3b3ab6 | balance decrease for bridge: Polygon Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x7c67654fca8537473b9cebfa779885204cad216d4403d8cd93239cd2223b7e6d | balance decrease for bridge: Arbitrum DAI L1 Escrow - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x0b5f51563d1ca3fb74a17af67db998cbc290fce19f1db716e7cc7cbfa1b2a9fc | balance decrease for bridge: Arbitrum Outbox - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x61b3d0c3987c7d10de55711acd8e4f9892db924373a9d879605a5732ddde80c3 | balance decrease for bridge: Arbitrum Delayed Inbox - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xf193941c3ca27034453cdded1c270495fdd1319e71e026c44980ad35e52bf3f2 | balance decrease for bridge: Lido Optimism L1 ERC20 Token Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x5514223d7d7bf9b1ec1eb5981eb471cb8eb7756fc615ca282de9a157b126694f | balance decrease for bridge: Wormhole Portal Token Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x98573cc633608a04c4a2aa963f58eaa5106fe20bbec33cd88fafeb5db293f2c0 | balance decrease for bridge: Near Rainbow Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x259952782ab7cb9ca42068dde334da5b2d49bf40963f63b3ae97ab25bfbb1046 | balance decrease for bridge: Stargate STG Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x4e94072946966e73c7333042f9285d7a88cced482241873a476d2de37b3faead | balance decrease for bridge: Stargate FRAX Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x7992c56564a94597eb3f952e0a603af471935c61d912f8ebf88f95f722df2df2 | balance decrease for bridge: Stargate ETH Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x19af004c822158e573668cf0bb39a2494faf471135676b08ab981327c44daf35 | balance decrease for bridge: Stargate SUSDT Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xf75e0714bd3a4f1df970c6d069ab3b457a2593846becef948751097d18d3286d | balance decrease for bridge: Stargate SUSDC Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xbc1f5127113aeb6332451d5a5e51bf0bdd707c45eca26083e312c2066819a739 | balance decrease for bridge: Symbiosis Finance Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x8c11dd81c639757b97f17de27a67d9b07bcd6c33f4b23ba94339728db460f03a | balance decrease for bridge: Synapse Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x67955dd1f25ab38cc5065d62453e73f77b8de43a79ad745c5f3816906c8fe815 | balance decrease for bridge: Gnosis xDai-ETH Omni Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0x639c7768c5c28a1623aa0748aa5aa8c07be20542803820a2186179ac9715ff73 | balance decrease for bridge: zkSync Era Diamond Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xd2f60f7626eaeb15c4026578e28f799afb1587db3a8e4cb5bf2d42b54e13933d | balance decrease for bridge: zkSync Era Bridge - Ethereum | BALANCE-DECREASE-ASSETS-PORTION-REMOVED | Exploitation |
| 0xe8527df509859e531e58ba4154e9157eb6d9b2da202516a66ab120deabd3f9f6 | attack simulation - Ethereum Mainnet | AK-ATTACK-SIMULATION-0 | Preparation |
| 0xee275019391109f9ce0de16b78e835c261af1118afeb1a1048a08ccbf67c3ea8 | Social Engineering Contract Creation Bot | SOCIAL-ENG-CONTRACT-CREATION | Preparation |
| 0xd935a697faab13282b3778b2cb8dd0aa4a0dde07877f9425f3bf25ac7b90b895 | Malicious Address Bot | AE-MALICIOUS-ADDR | Exploitation |
| 0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba | Sleep Minting | SLEEPMINT-3 | Preparation |
| 0xeab3b34f9c32e9a5cafb76fccbd98f98f441d9e0499d93c4b476ba754f8f0773 | Suspicious Contract Creation ML | SUSPICIOUS-CONTRACT-CREATION | Preparation |
| 0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8 | Anomalous Token Transfers Detection Machine Learning Bot | ANOMALOUS-TOKEN-TRANSFERS-TX | Exploitation |
| 0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f | Assets Drained | FORTA-1 | Exploitation |
| 0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb | Large Native Token Transfers Out | LARGE-TRANSFER-OUT | Money Laundering |
| 0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef | Aztec funded contract interaction | AK-AZTEC-PROTOCOL-FUNDED-ACCOUNT-INTERACTION-0 | Exploitation |
| 0xdccd708fc89917168f3a793c605e837572c01a40289c063ea93c2b74182cd15f | Aztec money laundering | AK-AZTEC-PROTOCOL-POSSIBLE-MONEY-LAUNDERING-NATIVE | Money Laundering |
| 0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb | CEX Funding bot | CEX-FUNDING-1 | Funding |
| 0xdccd708fc89917168f3a793c605e837572c01a40289c063ea93c2b74182cd15f | Aztec bot | AK-AZTEC-PROTOCOL-DEPOSIT-EVENT | Money Laundering |
| 0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad | Token Impersonation ML Bot | SUSPICIOUS-TOKEN-CONTRACT-CREATION | Funding |
| 0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef | Aztec Funding bot | AK-AZTEC-PROTOCOL-FUNDING | Funding |
| 0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46 | Malicious Account Funding Bot | MALICIOUS-ACCOUNT-FUNDING | Funding |
| 0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058 | New Account Funding | FLD_NEW_FUNDING | Funding |
| 0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058 | Account Funding | FLD_FUNDING | Funding |
| 0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058 | Money Laundering | FLD_Laundering | Money Laundering |
| 0x3858be37e155f84e8e0d6212db1b47d4e83b1d41e8a2bebecb902651ed1125d6 | high gas usage | NETHFORTA-1 | Exploitation |
| 0xbdb84cba815103a9a72e66643fb4ff84f03f7c9a4faa1c6bb03d53c7115ddc4d | Text msg sentiment analysis | NEGATIVE-ANGER-TEXT-MESSAGE | Money Laundering |
| 0xbdb84cba815103a9a72e66643fb4ff84f03f7c9a4faa1c6bb03d53c7115ddc4d | Text msg sentiment analysis | NEGATIVE-DISGUST-TEXT-MESSAGE | Money Laundering |
| 0xbdb84cba815103a9a72e66643fb4ff84f03f7c9a4faa1c6bb03d53c7115ddc4d | Text msg sentiment analysis | NEGATIVE-SADNESS-TEXT-MESSAGE | Money Laundering |
| 0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e | ChangeNow Bot | FUNDING-CHANGENOW-NEW-ACCOUNT | Funding |
| 0x7cfeb792e705a82e984194e1e8d0e9ac3aa48ad8f6530d3017b1e2114d3519ac | Large Profit Bot | LARGE-PROFIT | Exploitation |
| 0x43d22eb5e1e3a2a98420f152825f215e6a756f32d73882ff31d8163652242832 | Role change bot | ROLE-CHANGE | Preparation |
| 0xda967b32461c6cd3280a49e8b5ff5b7486dbd130f3a603089ed4a6e3b03070e2 | Suspicious flashloand contract creation | SUSPICIOUS-FLASHLOAN-PRICE-MANIPULATOR | Preparation |
| 0xabc0bb6fe5e0d0b981dec4aa2337ce91676358c6e8bf1fec06cc558f58c3694e | unusual native swaps | UNUSUAL-NATIVE-SWAPS | MoneyLaundering |
| 0x8b0976a3a59f09c6c4a0f66ffc8d8dcc028e6087b071ec2a82bb83ec5a99f181 | ABNORMAL-FUNCTION-CALL-DETECTED-1 | Exploitation |
| 0x8b0976a3a59f09c6c4a0f66ffc8d8dcc028e6087b071ec2a82bb83ec5a99f181 | ABNORMAL-EMITTED-EVENT-DETECTED-1 | Exploitation |

The following bots are used to mitigate FPs:
| BotID | Name | AlertId |
|-------|------|---------|
| 0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b | MEV account bot | MEV-ACCOUNT |
| 0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400 | High funding activity through TC | FUNDING-TORNADO-CASH-HIGH |
| 0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f | Positive reputation bot | POSITIVE-REPUTATION-1 |
| 0xe04b3fa79bd6bc6168a211bcec5e9ac37d5dd67a41a1884aa6719f8952fbc274 | Victim Notification bot | VICTIM-NOTIFICATION-1 |
In addtion, Etherscan tags are used for FP mitigation.
