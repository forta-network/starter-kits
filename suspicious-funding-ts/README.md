# Suspicious Funding Detector

## Description

This bot identifies when a new EOA receives funds from an address previously funded by Tornado Cash or Fixed Float, or from addresses flagged by the Attack Detector or this bot itself.

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
