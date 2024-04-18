# Tornado Cash Deposits

## Description

This detection bot triggers alerts for Tornado Cash Deposits

## Supported Chains

- Ethereum
- BSC
- Polygon
- Optimism
- Arbitrum

## Alerts

- TORNADO-CASH-DEPOSIT
  - Fired when a Tornado Cash deposit is identified
  - Metadata will contain the amount of transferred funds
  - Findings severity is High
  - Medium confidence labels (0.7) for attacker address
  - Metadata exposes the anomaly_score for the alert (calculated by dividing TC laundering tx by all transfer out tx)

## Test Data

The bot behaviour can be verified with the following transactions:

- Ethereum block 14602829-14602878 (beanstalk farms hack - https://rekt.news/beanstalk-rekt/)
- Ethereum block 14506449,14506451,14506454 (inverse finance hack - https://rekt.news/inverse-finance-rekt/)
