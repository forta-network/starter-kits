# Suspicious Contract Creation

## Description

This detection bot detects when a suspicious contract is created. A suspicious contract can take many forms; initially, this bot will alert on contracts that were created from Tornado cash funded accounts.

## Supported Chains

- Ethereum
- BSC
- Polygon
- Optimism
- Arbitrum

## Alerts

Describe each of the type of alerts fired by this agent

- SUSPICIOUS-CONTRACT-CREATION
  - Fired when a new contract is created
  - Metadata will contain the addresses observed in the created contract (either through storage or static analysis)
  - Findings severity will be Low
  - Low confidence labels (0.1) for attacker address and attacker_contract address are emitted
  - Metadata exposes the anomaly_score for the alert (calculated by dividing unverified contract creations by all contract creations)

- SUSPICIOUS-CONTRACT-CREATION-TORNADO-CASH'
  - Fired when a new contract is created by an account that was funded by tornado cash
  - Metadata will contain the addresses observed in the created contract (either through storage or static analysis)
  - Findings severity will be High
  - Low confidence labels (0.3) for attacker address and attacker_contract address are emitted
  - Metadata exposes the anomaly_score for the alert (calculated by dividing unverified contract creations by all contract creations)

## Test Data

The agent behaviour can be verified with the following transactions:

- Ethereum block 14464820,14465209 (revest finance hack - https://rekt.news/revest-finance-rekt/)
- Ethereum block 14602790 (beanstalk farms hack - https://rekt.news/beanstalk-rekt/)
