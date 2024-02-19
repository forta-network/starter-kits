# Early Attack Detector

## Description

This bot analyzes smart contracts as soon as they are deployed. In the case where the model predicts that a newly deployed smart contract is malicious, then the bot checks whether there has been suspicious funding for the deployer address. If there is, it raises an alarm, as it fulfills alarms for two attack phases [funding and preparation].

## Alerts

This bot only creates critical alerts when a contract has been funded with low KYC exchanges and the model is deemed malicious.