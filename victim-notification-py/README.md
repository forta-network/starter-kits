# Victim Notification Bot

## Description

This bot alerts on addresses that received victim notifications on-chain (transfer from special bot accounts with a message informing them about them falling victim)

This information can be used downstream to mitigate FPs or build additional intelligence on top of. 

## Supported Chains

- All EVM compatibile chains

## Alerts

Describe each of the type of alerts fired by this agent

- VICTIM-NOTIFICATION-1
  - Fired when an address receives a victim notification on-chain
  - Severity is always set to "info"
  - Type is always set to "info"

## Test Data

The agent behaviour can be verified with the following transactions:

- 0xc098c3068216ec0cb38da7c3d8cbf3946236d24ee4a9104feb4b686896d78ec9 (checkblockscanchat.eth notification)
