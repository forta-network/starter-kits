# Scam Detector Bot Release Notes

## v0.1.18
- incorporated [hard rug pull](https://explorer.forta.network/bot/0xc608f1aff80657091ad14d974ea37607f6e7513fdb8afaa148b3bff5ba305c15
), [soft rug pull](https://explorer.forta.network/bot/0x1a6da262bff20404ce35e8d4f63622dd9fbe852e5def4dc45820649428da9ea1
) and [rake token bot](https://explorer.forta.network/bot/0x36be2983e82680996e6ccc2ab39a506444ab7074677e973136fa8d914fc5dd11). New corresonding alerts are emitted: SCAM-DETECTOR-HARD-RUG-PULL, SCAM-DETECTOR-SOFT-RUG-PULL, and SCAM-DETECTOR-RAKE-TOKEN
- expanded coverage for native ice phishing to include NIP-5/ NIP-6 of the [native ice phishing bot](https://explorer.forta.network/bot/0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0). NIP-5/ NIP-6 are flagging native ice phishing where a contract is involved using static and dynamic detection approaches.
- incorporated [contract similarity bot](https://explorer.forta.network/bot/0x3acf759d5e180c05ecabac2dbd11b79a1f07e746121fc3c86910aaace8910560
); this bot will expand on previously raised alerts utilizing contract code similarity. A new alert is emitted: SCAM-DETECTOR-SIMILAR-CONTRACT
- refactored bot from utilizing graphQL library to handleAlert. This speeds up alerts.
- added sharding support to ensure no alerts are being dropped due to processing time of the alerts
- added persistence of findings/alerts cache, so no findings/alerts are lost upon a reassignment or restart
- fixes various parsing issues of base bot alerts
