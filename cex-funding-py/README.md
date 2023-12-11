# CEX Funding Bot

## Description

This agent detects when a new account is funded by a set of CEXes. Initially, it alerts on FixFloat, ChangeNOW, Bybit and MEXC exchanges.

## Supported Chains

- All chains

## Alerts


- CEX-FUNDING-1
  - Fired when a funding transaction is made to a new EOA using native assets in small amounts, specifically for transactions originating from certain CEXes known for less stringent KYC standards or a historical preference by attackers.
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Low confidence labels (0.3) for attacker address and attacker_contract address are emitted
  - Metadata exposes the anomaly_score for the alert (calculated by dividing unverified contract creations by all contract creations)
  - Metadata will contain amount funded, the funded address, as well as the name of the CEX

- CEX-FUNDING-2
  - Fired when a funding transaction is made to a new EOA using native asset in small amounts. It is particularly focused on transactions from mainstream or well-regulated centralized exchanges (CEXes) with robust KYC processes.
  - Severity is always set to "low"
  - Type is always set to "suspicious"
  - Low confidence labels (0.3) for attacker address and attacker_contract address are emitted
  - Metadata exposes the anomaly_score for the alert (calculated by dividing unverified contract creations by all contract creations)
  - Metadata will contain amount funded, the funded address, as well as the name of the CEX


## Test Data

The agent behaviour can be verified with the following transactions:

- 0x11aa33cf560a880cdc88785306d3f266aab0f22dd7ded7ddc99480ec89e9d634 (FixedFloat funding Team Finance Exploiter 1)
