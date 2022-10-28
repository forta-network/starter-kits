# CEX Funding Bot

## Description

This agent detects when a new account is funded by a set of CEXes. Initially, it alerts on FixFloat exchange.

## Supported Chains

- All chains

## Alerts

Describe each of the type of alerts fired by this agent

- CEX-FUNDING-1
  - Fired when a funding transaction is made to a new EOA using native asset in small amounts
  - Severity is always set to "low" 
  - Type is always set to "suspicious" 
  - Metadata will contain amount funded, the funded address, as well as the name of the CEX

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x11aa33cf560a880cdc88785306d3f266aab0f22dd7ded7ddc99480ec89e9d634 (FixFloat funding Team Finance Exploiter 1)
