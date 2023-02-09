# Malicious Smart Contract ML V3

## Description

This detection bot detects when a suspicious non-token or non-proxy contract is deployed. It uses an offline trained machine learning model that was built based on contract creation code contained in malicious and benign smart contracts.

This ML bot detected 2+ hacks before they happened:

- [$16M Team Finance Hack](https://twitter.com/FortaNetwork/status/1586044760476696577?s=20&t=x3ctj_DtFGWRQQCV9Jcujw)
- [$300K Olympus DAO Hack](https://twitter.com/FortaNetwork/status/1583559233852739584?s=20&t=x3ctj_DtFGWRQQCV9Jcujw)

For more technical details, please check out this blog post [How Forta’s Predictive ML Models Detect Attacks Before Exploitation](https://forta.org/blog/how-fortas-predictive-ml-models-detect-attacks-before-exploitation/)

### Model Configuration

**Data Used For Training**
- Trained on 15,443 benign and 174 malicious non-token and non-proxy Ethereum contracts. Datasets can be found at [forta-network/labelled-datasets](https://github.com/forta-network/labelled-datasets)

**Algorithm**

I borrowed a technique from natural language processing that analyzes smart contracts’ opcodes and extracts common and important opcodes found in malicious and benign contracts.

This technique is called TF-IDF (term frequency–inverse document frequency), and it extracts  numerical features from text (opcodes in this case). These features are then fed into a LogisticRegression model that predicts whether a contract is malicious or not.

* TF-IDF that extracts opcodes in chunks: unigrams, bigrams, trigrams, and 4-grams.
  * Example of unigram: PUSH1
  * Example of 4-gram: PUSH1 MSTORE PUSH1 CALLDATASIZE
  * Analyzing in chunks helps retain the relative position information of the smart contract opcodes.
* ML Model: SGD Classifier with loss set to “log_loss”

**Model Versions**

| **Model Version** | V1         | V2                        | V3                   |   |   |
|-------------------|------------|---------------------------|----------------------|---|---|
|  **Created Date** | 09/30/2022 |      11/05/2022           | 02/06/2023           |   |   |
| **Avg Precision** | 88.6%      | 73.36%                    | 87.78%               |   |   |
| **Avg Recall**    | 59.4%      | 48.37%                    | 55.195%              |   |   |
| **Avg F1-Score**  | 69.6%      | 53.97%                    | 62.077%              |   |   |
| **Alert Rate**    | 222.125    | 112.75 (9.5% less than V1)| TODO                 |   |   |
| **Notes**         |            | FP Mitigation for V1      | FP Mitigation for V2 |   |   |


* Average precision and recall were calculated via stratified 5-fold cross validation with decision threshold set to `0.5`
* Alert-rate = number of ethereum alerts daily (avg of 7 days)

**Improvements**

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
  - Fired when a new non-token and non-proxy contract is predicted as malicious.
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

The bot behaviour can be verified with the following transactions:

Ethereum Mainnet Transactions

- 0x05f548db9215621c49d845482f1b804d82697711ef691dd77d2a796f3881bd02 (Olympus Dao Hack)
- 0x36da5eed299bb5507759e9773ffd93d752f25a1c4c5fd60fcfbf41ec158742b2 (Phishing Scammer Monkey Drainer)
- 0xf4f51d7c1536d6b7729803ebe87aad5baad0053a505ecba88632a453f38cb6cc (Wintermute 2 Exploit)
- 0x3d6c7922d402b89a8970e943ac3d6d39f2fb6a9114fb8abc373385473eca31ac (Audius Exploit)
- 0xfb5a4d1aef98458f673f301c2e713613662ad621e8f57065a4da58a6401c0b4d (Inverse Finance Exploit)
- 0x3b88b285bf45740052ff71a74e74b60f564a46cffaaea3a56172702b085fc96d (Multichain exploiter)


