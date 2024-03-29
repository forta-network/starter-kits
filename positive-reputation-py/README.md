# Positive Reputation Bot

## Description

This bot identifies EOA associated with positive reputation in context of an attack (aka unlikely to be an attacker). The alert from this bot can be useful in context of FP mitigations.

The current implementation looks at the nonce, age and whether the EOA has deployed a high transaction count contract.

## Supported Chains

- Mainnet and Polygon (as luabase doesnt support the other chains at this point)

## Alerts

- POSITIVE-REPUTATION-1

  - Fired when an EOA with positive reputation has been identified by both nonce and age
  - Severity is always set to "info"
  - Type is always set to "info"

- POSITIVE-REPUTATION-2

  - Fired when an EOA with positive reputation has been identified by merely age
  - Severity is always set to "info"
  - Type is always set to "info"

- POSITIVE-REPUTATION-3
  - Fired when an EOA with positive reputation has been identified by age and having deployed a high tx count contract
  - Severity is always set to "info"
  - Type is always set to "info"

## Test Data

The bot behaviour can be verified with the following transaction:

- 0x8fc200713352ba40e98f118a98541cbf4722698f95ab2d36ceeee680e7012538 (0x3D871B217E22a9E3ed91082d50ADe2D97213e7A6 has positive reputation)
