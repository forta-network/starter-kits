# Positive Reputation Feed

## Description

This bot generates a positive reputation feed (both alerts as well as labels). It consumes from a few different base bots to generate this data:
- Positive Reputation Bot (0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f)
- MEV Bot (0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b)
- Victim Notification Bot (0xe04b3fa79bd6bc6168a211bcec5e9ac37d5dd67a41a1884aa6719f8952fbc274)

Currently this bot only emits alerts/ labels on EOAs. Contracts are coming soon.
Also note that the positive reputation is currently based on simple heuristic based base bots. ML models will replace those soon.

Positive reputation is a concept in which accounts deemed known good or trusted. Note, the definition here pertains primarily in context of whether an account is likely to engage in malicious behavior (protocol attacks, scams, phishing attacks, etc.)

## Supported Chains

- All EVM compatible chains

## Alerts

The following alerts are emitted by this bot. 

- POSITIVE-REPUTATION-1
  - Fired when an EOA has been deemed to have positive reputation by one or more basebots. 
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata contains which base bot assigned positive reputation to the account

## Alerts

The following labels are emitted by this bot. 

- Entity: Address
- EntityType: Address
- Label: "PositiveReputation"
- Confidence: A value between 0.0 and 1.0 indicative of the confidence in the label as per the following heuristic:
    0.3 when one bot assigned positive reputation
    0.5 when one or more bot assigned positive reputation


