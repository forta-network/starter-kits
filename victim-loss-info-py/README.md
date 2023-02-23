# Victim Loss Info Bot

## Description

This bot estimates the losses associated with end users. It consumes alerts from other bots

## Supported Chains

- All EVM compativle chains

## Alerts

Describe each of the type of alerts fired by this agent

- SCAM-DETECTOR-TRANSFER-FROM-LOSS
  - Fired when a transaction contains a Tether transfer over 10,000 USDT
  - Severity is always set to "low" (mention any conditions where it could be something else)
  - Type is always set to "info" (mention any conditions where it could be something else)
  - Mention any other type of metadata fields included with this alert


