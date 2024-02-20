# Early Attack Detector

## Description
The Early Attack Detector identifies protocol attacks in real-time;  before any digital assets are being stolen. It does so by combining Machine Learning (ML) analysis of newly deployed smart contracts with funding analysis for the deployer address. This version of the attack detector focuses on the two initial attack stages (Funding and Preparation).


## Approach

This bot has two different thresholds (for each compatible chain, as of version 0.0.1 only eth). The high-precision threshold represents a risk score focused on very-high precision, and slightly lower recall (i.e., if the model thinks a smart contract is malicious, it's very likely to be, but it may miss some smart contracts that are not so clear). The high-recall threshold focuses on finding as many malicious smart contracts as possible.

This bot only creates critical alerts. The logic to create the alerts is as follows:

1. Analyze the newly deployed smart contract, and obtain a risk score from the ML model.
1. If the risk score lays over the high-precision threshold (for compatible chains), a high-precision flag is added to the metadata, and an alert is raised.
1. If the risk score lays over the high-recall but under the high-precision thresholds, funding is checked. If the deployer address has received funding from low-KYC sources, a flag with the funding transaction is added to the metadata, and an alert is raised.
1. If the risk score is under both thresholds, no alert is raised.

## Metrics

Metrics are calculated using a 5-fold CV fashion (Divide data in 5 splits, train in 4 of them, predict on the unseen 5th, then calculate metrics over the whole dataset). 

|version|eth f1|eth p|eth r|oc f1|oc p|oc r|ehp f1|ehp p|ehp r|ochp f1|ochp p|ochp r|
|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|
|v0.0.1|0.38|0.24|0.94|0.47|0.31|0.95|0.57|0.98|0.40|-|-|-|

Legend:
- oc - other chains
- p - precision
- r - recall
- ehp - eth high precision
- ochp - other chains high precision