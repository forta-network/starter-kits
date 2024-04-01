# SWFT Swap Funding Bot

## Description

This bot detects transactions in the native currency from SWFT Swap to new EOA addresses, and to any EOA address when the amount sent is under a certain threshold. A new EOA address is defined here as one that has not sent over two transactions.

## Supported Chains

- Ethereum
- Binance Smart Chain
- Polygon
- Arbitrum
- Optimism
- Avalanche
- Fantom

## Alerts

- FUNDING-SWFT-SWAP-NEW-ACCOUNT

  - Fired when a new EOA address receives funds from SWFT Swap
  - Severity is always set to "Medium"
  - Type is always set to "info"
  - Metadata includes the amount funded, and the receiving address

- FUNDING-SWFT-SWAP-LOW-AMOUNT
  - Fired when a transaction from SWFT Swap is under a certain threshold
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the threshold for this bot, the amount funded, and the receiving address
