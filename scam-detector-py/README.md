# Scam Detector Feed

## Description

Individual alerts can have low precision (in other words false positives). This feed bot consumes alerts (both heuristics and ML model alerts) from a broad range of base bots that spans the various attack stages: funding, preparation, exploitation, and money laundering to tease out a highly precise signal along with a score that subscribers can threshold on. 

The bot essentially creates a feature vector per EOA that consists of the various alerts that triggered for the given EOA in the past X days. It then creates a score expressing the liklihood of this EOA being malicious and emits an alert. 

## Supported Chains

- All Forta supported chains

## Alerts

Describe each of the type of alerts fired by this bot

- SCAM-DETECTOR-ALERT-1
  - Fired when model scores the alerts from base bots for a given EOA highly
  - Severity is set dependent on the score of the alert: from medium to critical
  - Type is always set to "exploit" 
  - Meta data will contain additional context:
    - scammer_address: string
    - model features: the feature vector (essentially the counts of the alerts associated with the scammer address observed over the last X days)
    - threat categories: human readable threat categories the scammer is likely engaged in
  - Note: the detection bot will only alert once per EOA observed per severity (as such, an EOA could be reported through a medium severity alert and then a high severity alert, but not the other way around)

- SCAM-DETECTOR-FALSE-POSITIVE
  - Fired when an FP has been identified
  - Severity is always set to "info" 
  - Type is always set to "info" 

## Alerts
This bot also sets the following labels:

attacker: the scammer address