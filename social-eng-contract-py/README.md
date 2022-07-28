# Social Engineering Contract Creation Bot

## Description

This bot detects if a contract is created that is similar to existing contracts based on the contract address. 

## Supported Chains

- Ethereum
- BSC
- Polygon
- Arbitrum
- Avalanche
- Optimism
- Fantom

## Alerts

Fires an alert when a contract creation is detected which the first three and the last three characters of the contract are identical.

- SOCIAL-ENG-CONTRACT-CREATION
  - Fires when similar contract is created
  - Severity is always set to "high" (mention any conditions where it could be something else)
  - Type is always set to "exploit" (mention any conditions where it could be something else)

## Test Data

The agent behaviour can be verified with the following blocks (will trigger on tx 0x400098cc1780c1e6dfb0490fce70c438fe0710fc9e5ed4978ba2183ebdf3a58b), which is associated with ConvexFinance attack (https://twitter.com/Alexintosh/status/1540047636467748870?utm_source=substack&utm_medium=email).

- npm run tx 0xa19d76ea9a5470059966abd2ef193f6ef84a6328e3cac54d1c014bd0ba981a5d,0x400098cc1780c1e6dfb0490fce70c438fe0710fc9e5ed4978ba2183ebdf3a58b
