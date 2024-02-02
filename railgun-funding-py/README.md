# Railgun Funding Bot

## Description

This bot detects transactions in the native currency from Railgun to new EOA addresses, and to any EOA address when the amount sent is under a certain threshold. A new EOA address is defined here as one that has not sent over two transactions.

## Supported Chains

- Ethereum
- Binance Smart Chain
- Polygon
- Arbitrum

## Alerts

- FUNDING-RAILGUN-NEW-ACCOUNT

  - Fired when a new EOA address receives funds from Railgun
  - Severity is always set to "Medium"
  - Type is always set to "info"
  - Metadata includes the amount funded, and the receiving address

- FUNDING-RAILGUN-LOW-AMOUNT
  - Fired when a transaction from Railgun is under a certain threshold
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the threshold for this bot, the amount funded, and the receiving address

## Test Data

The bot behaviour can be verified with the following transaction:

- 0xe3ee96ff387fc5721e2667605f3a9562f69835b991f4e9d017a68cc01602536e (new EOA address, Ethereum)
- 0x39c43bda0c993e07e43891fc5f62d45f45392be93893d698a4bb393340ca14ce (low value, Polygon)
