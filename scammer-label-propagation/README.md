# Large Tether Transfer Agent

## Description

This agent propagates scammer labels towards unlabeled addresses. The flow is as follows:
1. A new label is published in an alert by one of the bots this agent is subscribed to. If the confidence is over a certain threshold, it triggers the whole process
1. Based on the address that was labeled as attacker, it collects the first order neighbours (any address that had a transaction from/to the central node). From every neighbour, it collects a representation of the address with aggregated measures, and of the transactions between any two addresses in the graph.
1. Using forta alerts, and subscribed bots, all the labels (both positive and negative) for any of the addresses are collected, and will be used afterwards.
1. Using the previous data a Graph Neural Network is trained. As the model don't have all the information from every node, the agent uses semi-supervised learning to learn from the known labels, and then it predicts on all the addresses that there is no information. From within those, when the model is confident (over a parameter) than an address is an attacker, this address is the published as findings.
## Supported Chains

- Ethereum

## Alerts

Describe each of the type of alerts fired by this agent

- FORTA-1
  - Fired when a transaction contains a Tether transfer over 10,000 USDT
  - Severity is always set to "low" (mention any conditions where it could be something else)
  - Type is always set to "info" (mention any conditions where it could be something else)
  - Mention any other type of metadata fields included with this alert
- SCAMMER-LABEL-PROPAGATION
  - Fired when an address that was previously unlabeled (based on the subscribed bots and configured sensitivity)
  is marked as a potential attacker
  - Severity is set to "medium"
  - Type is set to "suspicious"
  - There are labels attached to the alert, with the marked addresses and the probabilities of beng attackers 
  predicted by the model

## Test Data

The data used for the bot may change over time as it depends on transactions between addresses, and the current labels of an address. Nonetheless, there are a set of transactions to validate the behaviour in agent_test.py. 