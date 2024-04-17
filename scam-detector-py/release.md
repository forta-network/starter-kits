# Scam Detector Bot Release Notes

## 2.24.4 (prod - 4/3/2024)

- removed ADDRESS-POISONING-FAKE-TOKEN alert

## 2.24.4 (prod - 3/22/2024)

- Bug fixes

## 2.24.3 (prod - 3/19/2024)

- removed NIP-4 and NIP-7 passthrough alerts

## 2.24.2 (beta2 - 3/13/2024, prod - 3/13/2024)

- removed ICE-PHISHING-SUSPICIOUS-TRANSFER

## 2.24.1 (beta2 - 3/8/2024)

- X (Twitter) bot integration

## 2.24.0 (beta2 - 2/27/2024, prod - 3/6/2024)

- base bot parser bug fix
- add cache to block explorer calls

## 2.23.2 (beta2 - 1/11/2024, prod - 1/17/2024)

- Etherscan FP mitigation fix
- add detection logic of future contracts potentially deployed by scammer
- manual FP list check fix
- FP labels removal fix

## 2.23.1 (beta2 - 12/6/2023)

- added ICE-PHISHING-ZERO-NONCE-ALLOWANCE-TRANSFER

## 2.23.0 (beta2 - 12/5/2023)

- initial version

## 2.22.10 (beta2 - 11/29/2023, prod - 12/4/2023)

=======

## 2.22.11 (beta2 - 11/29/2023, prod - 12/7/2023)

- fix broken link in documentation

## 2.22.10 (beta2 - 11/29/2023, prod - 12/3/2023)

- fix issue 392

## 2.22.9 (beta2 - 11/29/2023)

- added ICE-PHISHING-ZERO-NONCE-ALLOWANCE

## 2.22.8 (beta2 - 11/28/2023)

- add cache size to debug errors

## 2.22.8 (beta2 - 11/28/2023)

- fix unique key label FP handling

## 2.22.7 (beta2 - 11/22/2023)

- fix beta2 handling

## 2.22.6 (beta2 - 11/22/2023, prod - 12/4/2023)

- remove pkc-3 and phishing ML bot (which is not used in prod)
- fixed manual list but

## 2.22.5 (beta2 - 11/20/2023)

- added attribution support (blocksec bot and manual list)

## 2.22.4 (beta2 - 11/8/2023)

- upgrade to sdk 0.1.45/0.1.25
- unique label logic

## 2.22.3 (beta2 - 11/2/2023)

- integrated SOCIAL-ENG-EOA-CREATION-NULL-ADDRESS to capture drainer addresses more comprehensively
- integrated NIP-9 to capture certain phishing related multicall attacks

## 2.22.2 (beta2 - 11/2/2023)

- upgrade to sdk 0.1.44/0.1.24
- fix issue #349

## 2.22.1 (beta2 - 11/1/2023)

- upgrade to sdk 0.1.44/0.1.24
- FP etherscan label fixes
- Reactive FP handling

## 2.22.0 (beta2 - 10/25/2023)

- upgrade to sdk 0.1.43/0.1.23

## 2.20.14 (11/29/2023 - beta (without private key compromise, phishing ML bot))

- reved cache to reset cache size

## 2.20.13 prod (11/21/2023 - prod (without private key compromise, phishing ML bot))

- update one pager

## 2.20.13 prod (without private key compromise, phishing ML bot)

- update sdk to 0.1.45

## 2.20.12 (beta - 10/21/2023, 10/23/2023 - prod (without private key compromise, phishing ML bot))

- fixed chain patrol bug
- changed one pager promoUrl

## 2.20.9

- fixed address poisoning zero value bug
- added unique key to reduce dupe alerts

## 2.20.7

- added one pager and updated documentation
- etherscan FP label mitigation
- Chainpatrol Bot Integration
- Fix https://github.com/forta-network/starter-kits/issues/321

## v2.20.5

- MM fix
- update scam detector sample to Sept data

## v2.20.4

- turned ADDRESS-POISONING-ZERO-VALUE to a passthrough alert (precision of this alert is 100%)

## v2.20.3 (September 20th - beta)

- debugged MM feature
- added new NIP-7 and NIP-8 alert ids for native ice phishing

## v2.20.2 (September 19th - beta (without metamask), September 19th - prod (without metamask, private key compromise, phishing ML bot))

- corrected description

## v2.20.0 (September 15th - beta (without metamask))

- fix of confidence value calculations
- incorporated social engineering contract base bot

## v2.19.2 (September 14th - beta (without metamask))

- reenabled expansion of ADDRESS-POISONING-FAKE-TOKEN in basebot parser as https://github.com/tf0rs/forta-address-poisoning-agent/issues/6 has been deemed not an issue
- reenable rake token bot and scammer association bot for prod
- incorporated quality_metrics.json to source confidence values from
- update long description
- update data sample
- update docker to contain ML libraries (step 1/2 for ML FP mitigation)

## v2.19.1 (August 24th - beta (without metamask), August 24th - prod (without metamask, private key compromise, ice phishing ML bot, scammer-association, rake token))

- removed expansion of ADDRESS-POISONING-FAKE-TOKEN in basebot parser due to issue https://github.com/tf0rs/forta-address-poisoning-agent/issues/6

## v2.19.0 (August 23rd - beta (without metamask), August 23rd - beta (without metamask, private key compromise, ice phishing ML bot, scammer-association, rake token))

- updated SDK to 0.1.38/0.1.21
- added FP check around contract tx count

## v2.18.3 (August 18th - beta (without metamask), August 21st - beta (without metamask, private key compromise, ice phishing ML bot, scammer-association, rake token))

- small bug fix

## v2.18.2 (August 17th - beta (without metamask), August 18th - prod (without metmask, private key compromise, ice phishing ML bot, scammer-association, rake token nor gas minting))

- integrate metamask phishing list
- refactor from graphQL to get_labels API
- fixed bug on scammer association

## v2.18.1 (August 4th - beta, August 8th - prod (without private key compromise, ice phishing ML bot, nor gas minting))

- updated README
- updated confidence values based on July precision measurements

## v2.18.0 (August 3rd - beta)

- swapped wash trading bot to community maintained bot
- updated RPC endpoints to utilized paid RPC endpoints increasing reliability of the bot
- integrated phish token alert from spam detection bot
- incorporated gas minting bot

## v2.17.7 (July 31st 2023 - beta, August 1st 2023 - prod (without private key compromise, ice phishing ML bot nor pig butchering))

- merge beta/ prod

## v2.17.6 (July 26th 2023 - beta)

- integrated pig butchering alert

## v2.17.5 (July 14th 2023 - beta)

- reconfigured PKC bot

## v2.17.4 (July 14th 2023 - beta)

- integrated scam notifier bot

## v2.17.3 (July 14th 2023 - beta)

- change error handling to emit finding as opposed to raising an exception (beta version only)

## v2.17.2 (July 14th 2023 - beta)

- better error handling around manual lists
- fix finding null issue

## v2.17.0 (July 11th 2023 - beta)

- add finding around error conditions
- add ability to alert on manual provided URLs and contract signatures

## v2.16.1 (July 11th 2023 - beta)

- ice phishing ML FP fix; increating threshold to 0.89 to mitigate a class of FPs

## v2.16.0 (July 6th 2023 - beta)

- incorporate new [ice phishing machine learning model](https://explorer.forta.network/bot/0x4ca56cfab479c4d41cf382383f6932f4bd8bfc6428bdeba82b634f7bf83ad333)

## v2.15.6 (July 17th prod (without private key compromise nor ice phishing ML bot))

- additional error handling fixes

## v2.15.5 (July 13th prod (without private key compromise nor ice phishing ML bot))

- additional manual list processing error handling

## v2.15.4 (July 12th prod (without private key compromise nor ice phishing ML bot))

- additional manual list processing error handling
- ice phishing ML FP fix; increating threshold to 0.89 to mitigate a class of FPs
- fixed issue around repeated manual finding emission

## v2.15.3 (June 29th 2023 - beta, July 5th prod (without private key compromise))

- added Urls to scam detector
- added some additional logging around decryption function

## v2.14.0 (June 28th 2023 - beta)

- integrated blocksec bots (addresses only)
- disabled running ML algo on passthrough alerts (this was enabled on beta for testing purposes)

## v2.13.2 (June 28th 2023 - beta)

- revamped version to match semantic versioning format
- added perf related logging
- removed shard from dynamo queries which were unnecessary; this is speeding up processing of the bot

## v0.2.13 (June 26th 2023 - beta)

- updated sdk to 0.1.33

## v0.2.12 (June 26th 2023 - beta)

- modified zettablock query for deployed contracts to reduce cost

## v0.2.11 (June 26th 2023 - beta)

- added explicit label version to labels; set to '2.0.0'

## v0.2.10 (June 21st 2023 - beta)

- remove combination heuristic as ML performs much better

## v0.2.9 (June 19th 2023 - beta)

- refactor of label to avoid deduping. Prior to version 0.2.2 a label was either scammer-eoa or scammer-contract with alertId in the metadata giving additional context. Now, the label will represent the high level 'scammer' label 'and additional infromation will be in the metadata.
- enhance handleFP function to remove specific labels as well as remove labels comprehensively
- replaced Allium with Zettablock to obtain deployed contract information
- updated ML model to unique alert id counts as features (v3)
- incorporate [token impersonation bot](https://explorer.forta.network/bot/0x6aa2012744a3eb210fc4e4b794d9df59684d36d502fd9efe509a867d0efa5127) as a passthrough alert: SCAM-DETECTOR-IMPERSONATING-TOKEN
- incorporate [private key compromise bot](https://explorer.forta.network/bot/0x6ec42b92a54db0e533575e4ebda287b7d8ad628b14a2268398fd4b794074ea03) as a passthrough alert: SCAM-DETECTOR-PRIVATE-KEY-COMPROMISE

## v0.2.1 (June 2nd 2023 - beta)

- add handler type into alert description

## v0.2.0 (June 1st 2023 - beta)

- introduction of additional handler that assesses alerts for a given EOA utililizing a supervised machine learning model for combination alerts. For version 0.2.0, if either the traditional combination heuristic or the ML model raise an alert, both alerts will be raised. A flag 'handler_type' in the metadata will allow to differentiate what algorithm was used.

## v0.1.33 (May 30th 2023 - beta)

- better handling of contracts that base bots alerted on. the associated scammer-contract labels will be decorated with the appropriate alert_id whereas other contracts deployed by the same scammer will receive an generic "SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT" alert_id.
- enhanced the handleTx contract creation to also add pool contract creations (e.g. uniswap pools)
- add original alert hashes in metadata of emitted label; unified meta data fields for different types of labels for consistency
- integrated new alerts from the [ice phishing bot](https://explorer.forta.network/bot/0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14): ICE-PHISHING-PULL-SWEEPTOKEN and ICE-PHISHING-OPENSEA-PROXY-UPGRADE. The former allows an scammer to create a transfer transaction using a multicall with pull and sweepToken function; the latter, the scammer can trick a user to upgrading the implementation of a user's opensea proxy contract to the attacker's implementation, which gives the attacker control over user's assets.
- integrated new alert from the [label propagation bot](https://explorer.forta.network/bot/0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848): SCAMMER-LABEL-PROPAGATION-2 which operates on a global as opposed to local label propagation graph model.

## v0.1.32 (May 18th 2023 - beta)

- upgrade to latest SDK (1.1.16/ 0.1.32)
- add SCAM-DETECTOR-SCAMMER-ASSOCIATION alert for when account is associated with a scammer account as per the [label propagation bot](https://explorer.forta.network/bot/0xcd9988f3d5c993592b61048628c28a7424235794ada5dc80d55eeb70ec513848)
- change alert caching to be per threat category, such that an alert/label gets emitted per threat category observed as opposed to only reporting the first threat category observed

## v0.1.26 (May 16th 2023 - beta)

- add SCAM-DETECTOR-SCAMMER-DEPLOYED-CONTRACT alert for when a known scammer deploys a contract

## v0.1.25 (May 16th 2023 - beta)

- add manual alerting capability; these alerts will be flagged with alert id: SCAM-DETECTOR-MANUAL- [ THREAT-CATEGORY ], e.g. SCAM-DETECTOR-MANUAL-ICE-PHISHING
- restricted the contract similarity bot to only operate on scams where a contract is essential:
  - SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING
  - SCAM-DETECTOR-ADDRESS-POISONER

## v0.1.21 (May 10 2023 - beta)

- tune confidence based on April precision numbers
- switched from fraudulent seaport order to the [scammer nft trader bot](https://explorer.forta.network/bot/0x513ea736ece122e1859c1c5a895fb767a8a932b757441eff0cadefa6b8d180ac), which covers additional on-chain market places (blur, looksrare and seaport). Renamed alertId SCAM-DETECTOR-FRAUDULENT-SEAPORT-ORDER to SCAM-DETECTOR-FRAUDULENT-NFT-ORDER as a result.

## v0.1.20 (May 4th 2023 - beta)

- incorporated [hard rug pull](https://explorer.forta.network/bot/0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15), [soft rug pull](https://explorer.forta.network/bot/0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1) and [rake token bot](https://explorer.forta.network/bot/0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11). New corresonding alerts are emitted: SCAM-DETECTOR-HARD-RUG-PULL, SCAM-DETECTOR-SOFT-RUG-PULL, and SCAM-DETECTOR-RAKE-TOKEN
- expanded coverage for native ice phishing to include NIP-5/ NIP-6 of the [native ice phishing bot](https://explorer.forta.network/bot/0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0). NIP-5/ NIP-6 are flagging native ice phishing where a contract is involved using static and dynamic detection approaches.

## v0.1.19 (May 9th 2023 - prod; May 1st 2023 - beta)

- refactored bot from utilizing graphQL library to handleAlert. This speeds up alerts.
- added sharding support to ensure no alerts are being dropped due to processing time of the alerts
- added persistence of findings/alerts cache, so no findings/alerts are lost upon a reassignment or restart
- fixes various parsing issues of base bot alerts
- incorporated [contract similarity bot](https://explorer.forta.network/bot/0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560); this bot will expand on previously raised alerts utilizing contract code similarity. A new alert is emitted: SCAM-DETECTOR-SIMILAR-CONTRACT
