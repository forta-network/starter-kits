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
  - Fired when a transaction contains a Tether transfer over 10,000 USDT
  - Severity is always set to "Medium" (mention any conditions where it could be something else)
  - Type is always set to "Suspicious" (mention any conditions where it could be something else)
  - Metadata includes:
    - `sender`: The address that sent funds
    - `receiver`: The address that received funds
