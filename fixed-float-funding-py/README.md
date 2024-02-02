# Fixed Float Funding

## Description

This bot detects transactions in the native currency from Fixed Float to new EOA addresses, and to any EOA address when the amount sent is under a certain threshold. A new EOA address is defined here as one that has not sent over two transactions.

## Supported Chains

- Ethereum
- BNB Chain
- Polygon
- Arbitrum
- Avalanche

## Alerts

- FUNDING-FIXED-FLOAT-NEW-ACCOUNT

  - Fired when a new EOA address receives funds from Fixed Float
  - Severity is always set to "Medium"
  - Type is always set to "info"
  - Metadata includes the amount funded, and the receiving address

- FUNDING-FIXED-FLOAT-LOW-AMOUNT
  - Fired when a transaction from Fixed Float is under a certain threshold
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata includes the threshold for this bot, the amount funded, and the receiving address

## Test Data

The bot behaviour can be verified with the following transaction:

- 0xddc95468ee754d7ad062c353ff7ae2d0fecaae35b2dac0fe22b370b3fb49a078 (Ethereum)
- 0x996b4c44315f72cc8d11e927cde071ea3e7b0289e64c8aa6a4acfa4c41e9e4f9 (BNB Chain)
