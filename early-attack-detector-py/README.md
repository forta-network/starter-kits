# Early Attack Detector

## Description

This bot analyzes smart contracts as soon as they are deployed. In the case where the model predicts that a newly deployed smart contract is malicious, then the bot checks whether there has been suspicious funding for the deployer address. If there is, it raises an alarm, as it fulfills alarms for two attack phases [funding and preparation].

## Alerts

This bot only creates critical alerts when a contract has been funded with low KYC exchanges and the model is deemed malicious.

## Versions metrics

The model has two different thresholds (for compatible chains). One focuses on having high recall, and is then filtered by account funding. The second one has very high precision, and doesn't need to have the funding flag for raising an alarm.

|version|eth f1|eth p|eth r|oc f1|oc p|oc r|ehp f1|ehp p|ehp r|ochp f1|ochp p|ochp r|
|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|
|v0.0.1|0.38|0.24|0.94|0.47|0.31|0.95|0.57|0.98|0.40|-|-|-|

Legend:
- oc - other chains
- p - precision
- r - recall
- ehp - eth high precision
- ochp - other chains high precision