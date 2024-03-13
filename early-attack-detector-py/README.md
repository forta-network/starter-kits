# Early Attack Detector

## Description
The Early Attack Detector identifies smart contract exploits (protocol attacks) in real-time; before any digital assets are stolen. It does so by combining Machine Learning (ML) analysis of newly deployed smart contracts with funding analysis of the deployer address. This version of the attack detector focuses on the two initial attack stages (Funding and Preparation). By doing so, the Early Attack Detector can greatly improve its precision rate.


## Approach

This bot has two different thresholds (for each compatible chain, as of version 0.0.1 only eth). The high-precision threshold represents a risk score focused on very-high precision, and slightly lower recall (i.e., if the model thinks a smart contract is malicious, it's very likely to be malicious, but it may miss some smart contracts that are not so clear). 

For a high-recall threshold, targeted more towards researchers and post-incident response, precision is slightly reduced in order to find as many malicious smart contracts as possible.

This bot only generates critical alerts. The logic behind these alerts is as follows:

1. Analyze all newly deployed smart contracts, and obtain a risk score from the ML model.
2. If the risk score reaches the high-precision threshold (for compatible chains), a high-precision flag is added to the metadata, and an alert is raised.
3. If the risk score reaches the high-recall threshold but under the high-precision thresholds, funding is checked. If the deployer address has received funding from low-KYC sources, a flag with the funding transaction is added to the metadata, and an alert is raised.
4. If the risk score is under both thresholds, no alert is raised.

## Alerts
- **EARLY-ATTACK-DETECTOR-1**, severity Critical. Alerts raised when the model is over the precision threshold and has been funded in the last 24 hours, or if the model precision is over the high precision threshold.
- **EARLY-AD-INFO**, [only for beta], severity Info. Auxiliary alerts for continuous improvement. 

## Metrics

Metrics are calculated using a 5-fold CV fashion (Divide data in 5 splits, train 4 of them, predict on the unseen 5th, then calculate metrics over the whole dataset). 

|version|eth f1|eth p|eth r|oc f1|oc p|oc r|ehp f1|ehp p|ehp r|ochp f1|ochp p|ochp r|
|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|
|v0.1.0|0.47|0.32|0.92|0.38|0.24|0.9|0.184|0.93|0.1|-|-|-|
|v0.0.1|0.54|0.39|0.9|0.36|0.23|0.89|0.78|0.89|0.69|0.26|0.84|0.15|

Legend:
- oc - other chains
- p - precision
- r - recall
- ehp - eth high precision
- ochp - other chains high precision
