# MEV Identification Bot

## Description

This bot identifies likely MEV accounts. This is useful to filter out FPs as some characteristics of MEV accounts and attacker accounts are similar.

It relies on a simple heuristic of multiple transfers in one transaction

## Supported Chains

- All EVM Chains

## Alerts

- MEV-ACCOUNT
  - Fired when a transaction is indicative of MEV activity (excessive trading across multiple DEXes)
  - Severity is always set to "info" 
  - Type is always set to "info" 
  - Metadata contains some stats on the tx, such as:
    - number of transfer events
    - number of unique tokens
    - number of contract addresses involved

## Test Data

The bot behaviour can be verified with the following transactions:

- 0xfdd22fd2521bd2a83ca3cb93f285bb54e4d36c0bad05d22401194859eca61c0b 
