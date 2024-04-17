# Thorchain Funding Bot

## Description

This bot detects transactions in the native currency from Thorchain to new EOA addresses, and to any EOA address when the amount sent is under a certain threshold. A new EOA address is defined here as one that has not sent over two transactions.

## Supported Chains

- Ethereum
- Binance Smart Chain
- Avalanche

## Alerts

- FUNDING-THORCHAIN-NEW-ACCOUNT

  - Fired when a new EOA address receives funds from Thorchain
  - Severity is always set to "Medium"
  - Type is always set to "info"
  - Metadata includes the amount funded, and the receiving address

- FUNDING-THORCHAIN-LOW-AMOUNT
  - Fired when a transaction from Thorchain is under a certain threshold
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the threshold for this bot, the amount funded, and the receiving address
