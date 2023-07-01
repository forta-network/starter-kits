# Disperse / Multisend batched transactions

## Description

Disperse / multisend are apps used to distribute ERC-20 to multiple addresses in one transaction.
Although they are useful to reduce gas fees by sending transactions in batches, many use them as part of their scam schemes. 

The goal of this bot is to alert when someone is using any of these apps in order to send native tokens or any other ERC-20 token.

## Supported Chains

- Ethereum
- List any other chains this agent can support e.g. BSC

## Alerts

Describe each of the type of alerts fired by this agent

- FORTA-1
  - Fired when a transaction contains a Tether transfer over 10,000 USDT
  - Severity is always set to "low" (mention any conditions where it could be something else)
  - Type is always set to "info" (mention any conditions where it could be something else)
  - Mention any other type of metadata fields included with this alert

## Deployment

The code is bundled in a Docker container.

## Tests

### Data

The agent behaviour can be verified with the following transactions:

- 0x3a0f757030beec55c22cbc545dd8a844cbbb2e6019461769e1bc3f3a95d10826 (15,000 USDT)
