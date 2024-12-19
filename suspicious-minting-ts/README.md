# Suspicious Minting

## Description

This bot detects transactions with suspicious token mints

## Supported Chains

- Ethereum
- BNB Chain
- Polygon
- Arbitrum
- Optimism
- Avalanche

## Alerts

- SUSPICIOUS-MINT-1

  - Fired when a token mint of over 50,000 USD is detected
  - Severity is always set to "High"
  - Type is always set to "Suspicious"
  - Metadata includes:
    - `initiator`: The address that initiated the mint
    - `token`: The address of the token
    - `usdValue`: The value of the token minted in USD
    - `txHash`: The hash of the transaction
    - `mintRecipient`: The address that the token is minted to
  - Labels include:
    - Label 1:
      - `entity`: The transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Attack"
      - `confidence`: The confidence level of the transaction being an attack (0-1), always set to 0.7
    - Label 2:
      - `entity`: The mint recipient address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Attacker"
      - `confidence`: The confidence level of the address being a victim (0-1), always set to 0.7

- SUSPICIOUS-MINT-2

  - Fired when a token mint of over 10,000 USD to a new EOA is detected
  - Severity is always set to "Medium"
  - Type is always set to "Suspicious"
  - Metadata includes:
    - `initiator`: The address that initiated the mint
    - `token`: The address of the token
    - `usdValue`: The value of the token minted in USD
    - `txHash`: The hash of the transaction
    - `mintRecipient`: The address that the token is minted to
  - Labels include:
    - Label 1:
      - `entity`: The transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Attack"
      - `confidence`: The confidence level of the transaction being an attack (0-1), always set to 0.6
    - Label 2:
      - `entity`: The mint recipient address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Attacker"
      - `confidence`: The confidence level of the address being a victim (0-1), always set to 0.6

- SUSPICIOUS-MINT-3
  - Fired when a token mint of unknown value to a new EOA is detected
  - Severity is always set to "Info"
  - Type is always set to "Suspicious"
  - Metadata includes:
    - `initiator`: The address that initiated the mint
    - `token`: The address of the token
    - `usdValue`: The value of the token minted in USD
    - `txHash`: The hash of the transaction
    - `mintRecipient`: The address that the token is minted to
  - Labels include:
    - Label 1:
      - `entity`: The transaction hash
      - `entityType`: The type of the entity, always set to "Transaction"
      - `label`: The type of the label, always set to "Attack"
      - `confidence`: The confidence level of the transaction being an attack (0-1), always set to 0.5
    - Label 2:
      - `entity`: The mint recipient address
      - `entityType`: The type of the entity, always set to "Address"
      - `label`: The type of the label, always set to "Attacker"
      - `confidence`: The confidence level of the address being a victim (0-1), always set to 0.5

## Test Data

The bot behaviour can be verified with the following transaction on Ethereum Mainnet:

- 0xa6d90abe17d17743a9cecab84bcefb0fd0bbfa0c61bba60fd2f680b0a2f077fe (Gala Exploit)
