# Title: Forta Alert Rate Monitoring Bot

## Description
This bot monitors a set of specified bot ID, alert ID, and chain ID combinations for alerts from the Forta network. It utilizes time series modeling to predict whether the alert rate is outside of the normal range. The bot's behavior is defined in a `constants.py` configuration file, and it uses the Facebook Prophet library for time series analysis.

## Supported Chains
Currently, the bot supports all EVM compatible chains

## Alerts
The bot emits the following alerts:

### ALERT-RATE-ANOMALY
- fires when the hourly alert rate for a given bot/alert/chain id combination falls outside of the expected range
- Severity and type is set to info