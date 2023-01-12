# Large Transfer Out Bot

## Description

This agent detects transactions with large native transfers that the account didnt hold X days ago, which could be indicative of money laundering. By itself, this bot will be quite noisy.

## Supported Chains

- all EVM supported chains

## Alerts

Describe each of the type of alerts fired by this agent

- LARGE-TRANSFER-OUT
  - Fired when a transaction contains a large native transfer and account didnt have those assets X days ago
  - Severity is always set to "low" (mention any conditions where it could be something else)
  - Type is always set to "suspicious" (mention any conditions where it could be something else)
  - Mention any other type of metadata fields included with this alert

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x39ed9312dabfe228ab03659192540da18b97f89eb7b89abaa9a6da03011e9668 (Gera Coin Attacker)
