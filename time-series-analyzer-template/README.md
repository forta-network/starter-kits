# Time Series Analyzer Template

## Description

This template takes a noisy alert and applies time series analysis to tease out statisically significant deviations that may be indicative of an attack.

To configure the template, specify the variables in the constants.py:
- BOT_ID: the bot id of the underlying bot whose alerts ought to be analyzed (e.g. '0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9')
- ALERT_NAME: the alert name of the underlying bot whose alerts ought to be analyzed (e.g. 'Reentrancy calls detected')

- CONTRACT_ADDRESS: the contract address filter to be applied (in other words, only consider the alerts where the contract address appears in the address list)

- BUCKET_WINDOW_IN_MIN: the period in minutes to which alerts will be aggregated to
- TRAINING_WINDOW_IN_BUCKET_SIZE: the training period time; since periodicity may be contained in the data, a sufficiently large window ought to be configured to capture this periodicity
- INTERVAL_WIDTH: the confidence interval size (default is 0.8) ranging from 0-1.0 where larger values indicate a narrow prediction band



## Supported Chains

- Any chain the underlying detection bot (whose alerts are utilized) are supported.

## Alerts

The detection bot will alert on alert frequencies of the underlyign detection bot that is being monitored that break out of the normal predicted range by the prophet time series analysis. Note, seemingly missing values will be replaced with the median of the data during the training window.

- UPSIDE-BREAKOUT
  - Fired when the alert freuqncy breaks out to the upside of the expected range.
  - Severity is always set to one level higher than the alert of the underlying detection bot.
  - Type is always set to the type of the underying deteciton bot.
  - Meta data will contain information about the expected value, the range boundary, and the actual value observed as well as the historical time series data and parameters of the model.

- DOWNSIDE-BREAKOUT
  - Fired when the alert freuqncy breaks out to the upside of the expected range.
  - Severity is always set to one level higher than the alert of the underlying detection bot.
  - Type is always set to the type of the underying deteciton bot.
  - Meta data will contain information about the expected value, the range boundary, and the actual value observed as well as the historical time series data and parameters of the model.

## Test Data

The agent behaviour should be verified given the time series data of the configured detection bot