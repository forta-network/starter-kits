# Alert Combiner

## Description

Individual alerts can have low precision (in other words raise false positives). This agent combines past alerts to separate the signal from noise. 

It does so with the realization that an attack usually consists of 4 distinct phases:
- funding (e.g. tornado cash funding)
- preparation (e.g. creation of an attacker contract)
- exploitation (e.g. draining funds from a contract)
- money laundering (e.g. sending funds to tornado cash)

As such, this detection bot combines previously raised alerts under the initiating address (i.e. the attacker address) for a given time window (2 calendar days, so between 24-48h) and emits a cricial alert when alerts from all four phases have been observed. 

As a result, the precision of this alert is quite high, but also some attacks may be missed. Note, in the case where attacks are missed, the broader set of detection bots deployed on Forta will still raise individual alerts that users can subscribe to.

## Supported Chains

- All Forta supported chains (note, it will appear that the agent only executes on one chain, but as it queries past Forta alerts, it essentially covers all chains)

## Alerts

Describe each of the type of alerts fired by this agent

- ALERT-COMBINER-1
  - Fired when alerts mapping to all 4 stages under one common EOA (the attacker address) have been observed
  - Severity is always set to "critical" 
  - Type is always set to "exploit" 
  - Meta data will contain the date range when attack took place, the attacker address, a list of detection bots that triggered that were utilized by this detection bot to make a decision as well as any of the transactions and addresses that were mentioned in any of the underlying alerts
  - Note: the block number that will be reported as part of this alert may be unrelated to the alert, but represents more of a timestamp on when the attack was discovered.
  - Note: the detection bot will only alert once per EOA observed

## Test Data

The agent behaviour can be verified with the following blocks (assuming a default time window):

- Fei Rari - block number 14685062 (date range: April 29-30 2022)
