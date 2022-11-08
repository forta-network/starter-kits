# Malicious Smart Contract ML V3

## Description

This detection bot detects when a suspicious non-token or non-proxy contract is deployed. It uses an offline trained machine learning model that was built based on contract creation code contained in malicious and benign smart contracts.

### Model Configuration

*Data Used For Training*
- Created date: 11/05/2022
- Trained on 15,443 benign and 174 malicious non-token and non-proxy Ethereum contracts. Datasets can be found at [forta-network/labelled-datasets](https://github.com/forta-network/labelled-datasets)

*Algorithm*

I borrowed a technique from natural language processing that analyzes smart contracts’ opcodes and extracts common and important opcodes found in malicious and benign contracts.

This technique is called TF-IDF (term frequency–inverse document frequency), and it extracts  numerical features from text (opcodes in this case). These features are then fed into a LogisticRegression model that predicts whether a contract is malicious or not.

* TF-IDF that extracts opcodes in chunks: unigrams, bigrams, trigrams, and 4-grams.
  * Example of unigram: PUSH1
  * Example of 4-gram: PUSH1 MSTORE PUSH1 CALLDATASIZE
  * Analyzing in chunks helps retain the relative position information of the smart contract opcodes.
* ML Model: SGD Classifier with loss set to “log_loss”

*Performance*

Using stratified 5-fold cross validation and decision threshold=0.5, the model predicted malicious contracts with average precision=73.36% and recall=48.37%.

This bot alerts 9.5% less than the [Malicious Smart Contract ML V2 Bot](https://github.com/forta-network/starter-kits/tree/main/malicious-smart-contract-ml-py).

*Improvements*

This model was trained only on Ethereum smart contracts, so it may make sense to create ML models for each chain trained on chain-specific smart contracts. For example, a model trained on BSC contracts.

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
  - Fired when a new non-token and non-proxy contract is created and predicted as malicious.
  - Metadata will include the following:
    - Link to OKO Contract Explorer to review decompiled contract code and ABI. This only works for Ethereum.
    - Function sighashes
    - ML model score and threshold
    - Addresses observed in the created contract (either through storage or static analysis)
    - Any wallet tags associated with the addresses. The bot queries the wallet tags from Luabase. This only works for Ethereum.
  - Finding type: Suspicious
  - Finding severity: High
  - Attack Stage: Preparation

## Test Data

The agent behaviour can be verified with the following transactions:

Ethereum Mainnet Transactions

- 0x05f548db9215621c49d845482f1b804d82697711ef691dd77d2a796f3881bd02 (Olympus Dao Hack)
- 0x36da5eed299bb5507759e9773ffd93d752f25a1c4c5fd60fcfbf41ec158742b2 (Phishing Scammer Monkey Drainer)
- 0xf4f51d7c1536d6b7729803ebe87aad5baad0053a505ecba88632a453f38cb6cc (Wintermute 2 Exploit)
- 0x3d6c7922d402b89a8970e943ac3d6d39f2fb6a9114fb8abc373385473eca31ac (Audius Exploit)
- 0xfb5a4d1aef98458f673f301c2e713613662ad621e8f57065a4da58a6401c0b4d (Inverse Finance Exploit)
- 0x3b88b285bf45740052ff71a74e74b60f564a46cffaaea3a56172702b085fc96d (Multichain exploiter)


