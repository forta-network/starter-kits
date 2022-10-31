# Malicious Smart Contract ML

## Description

This detection bot detects when a suspicious smart contract is deployed. It uses an offline trained machine learning model that was built based opcodes contained in malicious and benign smart contracts.

This ML bot detected two hacks before they happened:

- [$16M Team Finance Hack](https://twitter.com/FortaNetwork/status/1586044760476696577?s=20&t=x3ctj_DtFGWRQQCV9Jcujw)
- [$300K Olympus DAO Hack](https://twitter.com/FortaNetwork/status/1583559233852739584?s=20&t=x3ctj_DtFGWRQQCV9Jcujw)

## Supported Chains

- Ethereum
- BSC
- Polygon
- Optimism
- Arbitrum
- Avalanche
- Fantom

## Alerts

- SUSPICIOUS-CONTRACT-CREATION
  - Fired when a new contract is created and predicted as malicious.
  - The metadata will contain the addresses observed in the created contract (either through storage or static analysis) as well as the machine learning score.
  - Finding type: Suspicious
  - Finding severity: High
  - Attack Stage: Preparation

## Test Data

The agent behaviour can be verified with the following transactions:

Ethereum Mainnet Transactions
- 0xf4f51d7c1536d6b7729803ebe87aad5baad0053a505ecba88632a453f38cb6cc (Wintermute 2 Exploit)
- 0x3d6c7922d402b89a8970e943ac3d6d39f2fb6a9114fb8abc373385473eca31ac (Audius Exploit)
- 0xfb5a4d1aef98458f673f301c2e713613662ad621e8f57065a4da58a6401c0b4d (Inverse Finance Exploit)
- 0x3b88b285bf45740052ff71a74e74b60f564a46cffaaea3a56172702b085fc96d (Multichain exploiter)

