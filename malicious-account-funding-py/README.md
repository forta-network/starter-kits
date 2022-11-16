# Malicious Account Funding Bot

## Description

This agent reports when an account is funded by a known malicious account (sourced from luabase tags)

## Supported Chains

- Ethereum, Polygon (limited to the tags available on luabase)

## Alerts

Describe each of the type of alerts fired by this agent

- MALICIOUS-ACCOUNT-FUNDING
  - Fired when a funding (native asset only) transaction takes place from a known malicious account
  - Severity is always set to "high" 
  - Type is always set to "suspicious" 
  - Metadata contains the funder address and tag

## Test Data

The agent behaviour can be verified with the following transactions:

- 0x382d8c82a6f36c28d886bc0bfca3f28d83eb4395ef07864bfa8aece87a19aa55 (Fake_Phishing6284)
