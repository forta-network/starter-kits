# End User Attack Feed 

## Description

This bot generates a negative reputation feed (both alerts as well as labels) focused on end user attacks. It consumes from a few different base bots to generate this data:
- Scam Detector (0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23)

## Supported Chains

- All EVM compatible chains

## Alerts

The following alerts are emitted by this bot. 

- NEGATIVE-REPUTATION-END-USER-ATTACK-1
  - Fired when a end user attack has been observed. 
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Metadata contains which base bot, alert_id and alert_hash responsible for the threat intelligence. 

## Alerts

The following labels are emitted by this bot. 

- Entity: Address
- EntityType: Address
- Label: "Attacker"
- Confidence: 0.6
