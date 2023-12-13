# ChangeNow Funding Bot

## Description

This bot detects transactions in the native currency from ChangeNow hot wallets to new EOA addresses, and to any EOA address when the amount sent is under a certain threshold. A new EOA address is defined here as one that has not sent any transactions.

## Supported Chains

- Ethereum
- Binance Smart Chain
- Polygon

## Alerts


- FUNDING-CHANGENOW-NEW-ACCOUNT
  - Fired when a transaction from the ChangeNOW hot wallet is to a new EOA address
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the amount funded, and the receiving address

- FUNDING-CHANGENOW-LOW-AMOUNT
  - Fired when a transaction from the ChangeNOW hot wallet is under a certain threshold
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the threshold for this agent, the amount funded, and the receiving address

## Test Data

The bot behaviour can be verified with the following transactions:

- 0xc4af34bc84bbdda599ccf915a9c6cb62481899086767480212a4b28f4636c0f7 (new EOA address)
- 0x25678c1fd55f14c6a04e6c54c21bf13b51d84974db8299dafe86dd755d3a6b64 (low funding amount)
