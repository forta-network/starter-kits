# Suspicious Funding Detector

## Description

This bot identifies when a new EOA receives funds from addresses:
- previously funded by either Tornado Cash or Fixed Float
- flagged by the Attack Detector
- identified in the _True Positive List_ also used by the Early Attack Detector
- or this bot itself

## Supported Chains

- Ethereum
- BNB Chain
- Fantom
- Polygon
- Optimism
- Arbitrum
- Avalanche

## Alerts

- SUSPICIOUS-FUNDING
  - Fired when a new EOA is funded by a suspicious address
  - Severity is always set to "Medium"
  - Type is always set to "Suspicious"
  - Metadata includes:
    - `sender`: The address that sent funds
    - `receiver`: The address that received funds
    - `origin`: The initial funding source
    - `hops`: The count of intermediary transactions that occurred between the initial funding source and the final receiver.
- MALICIOUS-FUNDING
  - Fired when a new EOA is funded by an address identified in the _True Positive List_
  - Severity is always set to "Critical"
  - Type is always set to "Exploit"
  - Metadata includes:
    - `sender`: The address that sent funds
    - `receiver`: The address that received funds
    - `origin`: The initial funding source
    - `hops`: The count of intermediary transactions that occurred between the initial funding source and the final receiver.
