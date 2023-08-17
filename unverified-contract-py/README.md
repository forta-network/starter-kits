# Unverified Contract Creation Agent

## Description

This agent alerts when a new contract is created with unverified source code as per Etherscan.

## Supported Chains

- All EVM compatible chains; if tracing is supported, the bot is able to check contract creations by contracts

## Alerts

Describe each of the type of alerts fired by this agent

- UNVERIFIED-CODE-CONTRACT-CREATION
  - Fires when a contract is created but blockchain explorer has no verified code for the contract
  - Severity is always set to "medium" 
  - Type is always set to "suspicious"
  - Low confidence labels (0.3) for attacker address and attacker_contract address are emitted
  - Metadata exposes the anomaly_score for the alert (calculated by dividing unverified contract creations by all contract creations)

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x531e42376038809d98fd488edddb33126431bda870bd3f43984025486a3f4f68 (Fei Rari attacker contract)
- 0x16718a6df144de749035e4763946ad56d3dfaeb5d151a82f913698fa4ae28c3d (Conic Finance Exploiter contract)
