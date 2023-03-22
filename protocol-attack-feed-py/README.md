# Protocol Attack Feed 

## Description

This bot generates a negative reputation feed (both alerts as well as labels) focused on protocol attacks. It consumes from a few different base bots to generate this data:
- Attack Detector V1 (0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1)

## Supported Chains

- All EVM compatible chains

## Alerts

The following alerts are emitted by this bot. 

- NEGATIVE-REPUTATION-PROTOCOL-ATTACK-1
  - Fired when a protocol attack has been observed. 
  - Severity is always set to "critical"
  - Type is always set to "exploit"
  - Metadata contains which base bot, alert_id and alert_hash responsible for the threat intelligence. 

## Alerts

The following labels are emitted by this bot. 

- Entity: Address
- EntityType: Address
- Label: "Attacker"
- Confidence: 0.6

- Entity: Address
- EntityType: Address
- Label: "Victim"
- Confidence: 0.4

- Entity: Address
- EntityType: Unknown
- Label: >victim_name<
- Confidence: 1.0



