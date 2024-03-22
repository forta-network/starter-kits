# Attack Detector Bot Release Notes

## v3.54.2 (Mar 22th 2024: beta2)

- Bug fixes

## v3.54.1 (Mar 5th 2024: beta2, Mar 6th 2024: prod)

- ICE-PHISHING-SUSPICIOUS-TRANSFER alert removal

## v3.54.0 (Feb 29th 2024: beta2)

- Entity clustering logic removal
- Shards reduction

## v3.53.2 (Feb 22th 2024: beta2, Feb 29th 2024: prod)

- New funding bots integration (Thorchain, eXch)

## v3.53.1 (Feb 9th 2024: beta2)

- Polygon validators FP fix
- Integrated funding stage alerts from all chains

## v3.53.0 (Feb 2nd 2024: beta2, Feb 5th 2024: prod)

- Funding stage alert expiry time extension
- New funding bots integration (Union Chain, Railgun, Fixed Float, Squid)
- Performance Optimizations

## v3.52.6 (Feb 2nd 2024: prod)

- Remove Funding & Laundering Detection bot

## v3.52.5 (Dec 18th 2023: beta2, Dec 18th 2023:prod)

- After rebase

## v3.52.5 (Dec 15th 2023: beta2)

- Added decryption of blocksec alerts

## v3.52.3 (Dec 1st 2023: beta2)

- Added consensus mechanism

## v3.52.2 (Dec 1st 2023: beta2)

- Reactive FP mitigation

## v3.52.1 (Nov 29 2023: beta2)

- Fix bug 372

## v3.52.0 (Nov 15 2023: beta2)

- Added new MEV bot for FP mitigation

## v3.51.7 (Dec 6 2023: prod)

- updated documentation

## v3.51.6 (Nov 17 2023: beta2, Nov 17 2023: prod)

- updated promo URL

## v3.51.5 (Nov 14 2023: beta2, Nov 14 2023: prod)

- update to sdk 0.1.45

## v3.51.4 (Nov 3 2023: beta2, Nov 6 2023: prod)

- redeploy

## v3.51.4 (Oct 31 2023: beta2)

- etherscan label FP mitigation
- addition of error log findings
- new alert ID firing on funding/preparation
- bug fixes

## v3.51.3 (Oct 25 2023: beta2)

- integrate blocksec bot by introducing passthrough alertID (ATTACK-DETECTOR-7)
- update to sdk 0.1.43

## v3.50.4 (Sept 25 2023: beta)

- integrated ownership transfer bot
- added POSITIVE-REPUTATION-2 FP mitigation
- update to sdk 0.1.41

## v3.50.3 (Seot 12 2023: beta, Sept 19 2023: prod)

- update to sdk 0.1.40/0.1.21
- updated long description

## v3.50.1 (August 21 2023: beta)

- add unique_key to finding to reduce duplicate alerts
- fixed bug of dynamo pointing to test tag
- update to sdk 0.1.38/0.1.20

## v3.50.0 (August 8 2023: beta)

- add more bridge balance monitoring bots
- add fp_list and manual_alert_list
- introduce prod and test dynamo DB item prefix
- propagate bloom filter
- dynamo DB persistence and sharding

## v3.46.3 (August 4 2023: beta, August 7 2023: prod)

- updated package.json with new fields
- update SDK to 0.1.34

## v3.46.1 (July 5 2023: beta, July 5 2023: prod)

- increase redundancy of bot on the network

## v3.46.0 (June 29 2023: beta, June 29 2023: prod)

- additional FP mitigation around scammers

## v3.45.2 (June 29 2023: beta, June 29 2023: prod)

- updated SDK to version 0.1.33

## v3.45.1 (June 28 2023: beta, June 29 2023: prod)

- add date limit on zettablock to obtain contract creation more cheaply
- small adjustments to high precision logic to also fire if there are more than 1 high precision bot that triggered
- updated SDK to version 0.1.32
- change versioning scheme

## v0.3.43 (June 12 2023: beta, June 14 2023: prod)

- moved from allium to zettablock to obtain contract creations

## v0.3.42 (June 1 2023: beta, June 2 2023: prod)

- added large profit bot to high precision bots
- relaxed logic to fire when more than one high precision bots fire
- added FP mitigation logic for Polygon validators

## v0.3.41 (May 11 2023: beta, May 31 2023: prod)

- Attack detector often reports on end user related attacks, such as rake tokens, rug pulls as these attacks often follow the same patterns as a protocol exploit of funding, preparation, exploitation, and money laundering. The attack detector is supposed to only emit protocol exploits though. In this version, a new filter has been added where EOAs that are associated with specific end user attacks are degraded to a new alert Id: ATTACK-DETECTOR-6 (only will emitted in the beta version of the bot). The end user attacks are sourced from three bots: [hard rug pull](https://explorer.forta.network/bot/0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15), [soft rug pull](https://explorer.forta.network/bot/0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1) and [rake token bot](https://explorer.forta.network/bot/0 x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11)

## v0.3.40 (May 10 2023: beta)

- Added [generic anomaly base bot](https://explorer.forta.network/bot/0x644b77e0d77d68d3841a55843dcdd61840ad3ca09f7e1ab2d2f5191c35f4a998).

## v0.3.39 (May 10 2023: prod, May 9 2023: beta)

- Increased redundancy of this bot. It is now deployed on 6 scan nodes as opposed to 3.
- upgraded to SDK 0.1.29.
