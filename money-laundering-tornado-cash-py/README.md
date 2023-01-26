# Money Laundering through Tornado Cash

## Description

This detection bot detects when numerous large transfers are made to Tornado Cash potentially indicative of money laundering activity post-hack.

## Supported Chains

- Ethereum
- BSC
- Polygon
- Optimism
- Arbitrum

## Alerts

Describe each of the type of alerts fired by this agent

- POSSIBLE-MONEY-LAUNDERING-TORNADO-CASH
  - Fired when possible money laundering is identified
  - Metadata will contain amount if funds transferred in the block range specifified in the configuration
  - Findings severity will be High
  - Low confidence labels (0.5) for attacker address 
  - Metadata exposes the anomaly_score for the alert (calculated by dividing TC laundering tx by all transfer out tx)

## Test Data

The agent behaviour can be verified with the following transactions:

- Ethereum block 14602829-14602878 (beanstalk farms hack - https://rekt.news/beanstalk-rekt/)
- Ethereum block 14506449,14506451,14506454 (inverse finance hack - https://rekt.news/inverse-finance-rekt/)
