# Union Chain Funding

## Description

This bot detects transactions in the native currency from Union Chain to new EOA addresses, and to any EOA address when the amount sent is under a certain threshold. A new EOA address is defined here as one that has not sent over two transactions.

## Supported Chains

- Ethereum

## Alerts

- FUNDING-UNION-CHAIN-NEW-ACCOUNT

  - Fired when a new EOA address receives funds from Union Chain
  - Severity is always set to "Medium"
  - Type is always set to "info"
  - Metadata includes the amount funded, and the receiving address

- FUNDING-UNION-CHAIN-LOW-AMOUNT
  - Fired when a transaction from Union Chain is under a certain threshold
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the threshold for this bot, the amount funded, and the receiving address

## Test Data

The bot behaviour can be verified with the following transaction:

- 0x8b3ac1b28e817b8bb2d284cb64516604e8f39bfe778f2e74949f498cef9ee9c6 (Radiant Exploit)
- 0x39c43bda0c993e07e43891fc5f62d45f45392be93893d698a4bb393340ca14ce (low value, Polygon)
