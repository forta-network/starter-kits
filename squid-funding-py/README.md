# Squid Funding Bot

## Description

This bot detects transactions in the native currency from Squid to new EOA addresses, and to any EOA address when the amount sent is under a certain threshold. A new EOA address is defined here as one that has not sent over two transactions.

## Supported Chains

- Ethereum
- Binance Smart Chain
- Polygon
- Arbitrum
- Optimism
- Fantom
- Avalanche
- Base

## Alerts

- FUNDING-SQUID-NEW-ACCOUNT

  - Fired when a new EOA address receives funds from Squid
  - Severity is always set to "Medium"
  - Type is always set to "info"
  - Metadata includes the amount funded, and the receiving address

- FUNDING-SQUID-LOW-AMOUNT
  - Fired when a transaction from Squid is under a certain threshold
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the threshold for this bot, the amount funded, and the receiving address

## Test Data

The bot behaviour can be verified with the following transaction:

- 0x1f76c816bdbd72633ca00d64c6607b6e26fb14c87388cfce298f388c898bf8ef (new EOA address, Ethereum)
