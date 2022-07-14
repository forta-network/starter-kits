# Time Series Analyzer Template

## Description

This template takes a noisy alert and applies time series analysis to tease out statisically significant deviations that may be indicative of an attack. The Prophet library (https://facebook.github.io/prophet/) is used to represent the alert data as a time series, build a model, and predict the expected range of alert volume for the given BUCKET. If it breaks out of the range, an alert is triggered. 

To configure the template, specify the variables in the constants.py:
- BOT_ID: the bot id of the underlying bot whose alerts ought to be analyzed (e.g. '0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9')
- ALERT_NAME: the alert name of the underlying bot whose alerts ought to be analyzed (e.g. 'Reentrancy calls detected')

- CONTRACT_ADDRESS: the contract address filter to be applied (in other words, only consider the alerts where the contract address appears in the address list)

- BUCKET_WINDOW_IN_MIN: the period in minutes to which alerts will be aggregated to
- TRAINING_WINDOW_IN_BUCKET_SIZE: the training period time; recommended to cover training period during which the periodicity can be observed, so in case of a bucket_window_in_minutes of 5 minnutes, 12 * 24 * 7 = 1 week period. This is the lookback period the time series model will be built on. It is recommended to at least have 7 days so weekly periodicity can be taken into account.
- INTERVAL_WIDTH: the confidence interval size (default is 0.8) ranging from 0-1.0 where larger values indicate a narrow prediction band
- TIMESTAMP_QUEUE_SIZE: the number of timestamps that are held in the queue


## Supported Chains

- Any chain the underlying detection bot (whose alerts are utilized) are supported.

## Alerts

The detection bot will alert on alert frequencies of the underlying detection bot that is being monitored that break out of the normal predicted range by the prophet time series analysis. Note, seemingly missing values will be replaced with the median of the data during the training window.

- UPSIDE-BREAKOUT
  - Fired when the alert frequency breaks out to the upside of the expected range.
  - Severity is passed through from alert of the underlying detection bot.
  - Type is always set to the type of the underlying detection bot.
  - Meta data will contain information about the expected value, the range boundary, and the actual value observed.

- DOWNSIDE-BREAKOUT
  - Fired when the alert frequency breaks out to the downside of the expected range.
  - Type is always set to the type of the underlying detection bot.
  - Meta data will contain information about the expected value, the range boundary, and the actual value observed.

## Test Data

The agent behaviour should be verified given the time series data of the configured detection bot