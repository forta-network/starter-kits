# Attack Detector Bot Release Notes

## v3.51.2 (Oct 18 2023: beta)
- Added new MEV bot for FP mitigation

## v3.51.0 (Oct 17 2023: beta)
- Added FP mitigation for chain 1

## v3.50.3 (Seot 12 2023: beta)
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
