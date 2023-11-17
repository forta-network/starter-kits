# Role Change Detection Agent

## Description

This agent detects transactions triggering role changes in smart contracts.

## Supported Chains

- Ethereum
- Binance Smart Chain
- Polygon
- Arbitrum
- Optimism
- Fantom
- Avalanche

## Alerts

Describe each of the type of alerts fired by this agent

- ROLE-CHANGE
  - Fired when a transaction to a contract invokes a function call that appears to trigger a role change
  - Severity is always set to "medium"
  - Type is always set to "suspicious"
  - Metadata includes the key words that triggered the alert, the function call made in the transaction, and the anomaly score

## Test Data

The agent behaviour can be verified with the following transactions:

- 0xbdc28a3d1b8dc6ccaa88c30839b0c0b8275c6e72fe23881d4eddd93c1e7e3c9c (calls transferOwnership(address))
