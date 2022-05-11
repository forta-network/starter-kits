# Unverified Contract Creation Agent

## Description

This agent alerts when a new contract is created with unverified source code as per Etherscan.

## Supported Chains

- Ethereum

## Alerts

Describe each of the type of alerts fired by this agent

- UNVERIFIED-CODE-CONTRACT-CREATION
  - Fires when a contract is created but Etherscan has no verified code for the contract
  - Severity is always set to "medium" 
  - Type is always set to "suspicious"

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x531e42376038809d98fd488edddb33126431bda870bd3f43984025486a3f4f68 (Fei Rari attacker contract)
