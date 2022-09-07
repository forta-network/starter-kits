# Malicious Smart Contract ML

## Description

This detection bot detects when a malicious smart contract is deployed. It uses an offline trained machine learning model that was built based on function signature hashes contained in malicious and benign smart contracts.

## Supported Chains

- Ethereum
- BSC
- Polygon
- Optimism
- Arbitrum

## Alerts

Describe each of the type of alerts fired by this agent

- MALICIOUS-CONTRACT-CREATION
  - Fired when a new contract is created
  - Metadata will contain the addresses observed in the created contract (either through storage or static analysis) as well as the machine learning score
  - Findings severity will be High

## Test Data

The agent behaviour can be verified with the following transactions:

- Ethereum tx 0x3b88b285bf45740052ff71a74e74b60f564a46cffaaea3a56172702b085fc96d (Multichain exploiter)