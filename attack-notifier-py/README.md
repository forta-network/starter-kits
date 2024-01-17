# Attack Notifier Bot

## Description

Bot that raises an alert when a publicly disclosed attack has been detected by Forta's Attack Detector. It does so by subscribing to Attack Detector alerts, waiting for an hour and then assessing whether Etherscan has an exploiter/ hack label. If so, an alert is emitted.

## Supported Chains

- All chains

## Alerts

Describe each of the type of alerts fired by this agent

- ATTACK-NOTIFIER-1
  - Fired when an Attack Detector alert has an Etherscan label an hour after the alert was raised
  - Description contains the EOAs and label
  - Source alert points to the Attack Detector alert
  - Severity is always set to "critical" 
  - Type is always set to "exploit" 

## Test Data

The agent behaviour can be verified by running npm run alert alertHash on a recent alert where an appropriate Etherscan label exists
