# Malicious Token Smart Contract ML

## Description

This detection bot detects when a suspicious (erc20/erc721/erc1155/erc777) token contract is deployed. It uses an offline trained machine learning model that was built based on contract creation code contained in malicious and benign smart contracts.

### Model Configuration

*Data Used For Training*
- Created date: 10/29/2022
- Trained on 88,368 benign and 391 malicious token contracts. Datasets can be found at [forta-network/labelled-datasets](https://github.com/forta-network/labelled-datasets)

*Algorithm*

I borrowed a technique from natural language processing that analyzes smart contracts’ opcodes and extracts common and important opcodes found in malicious and benign contracts.

This technique is called TF-IDF (term frequency–inverse document frequency), and it extracts  numerical features from text (opcodes in this case). These features are then fed into a LogisticRegression model that predicts whether a contract is malicious or not.

* TF-IDF that extracts opcodes in chunks: unigrams, bigrams, trigrams, and 4-grams.
  * Example of unigram: PUSH1
  * Example of 4-gram: PUSH1 MSTORE PUSH1 CALLDATASIZE
  * Analyzing in chunks helps retain the relative position information of the smart contract opcodes.
* ML Model: SGD Classifier with loss set to “log_loss”

*Performance*

Using stratified 5-fold cross validation and decision threshold=0.5, the model predicted malicious contracts with average precision=84.1% and recall=38.1%.

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
  - Fired when a new (erc20/erc721/erc1155/erc777) token contract is created and predicted as malicious.
  - The metadata will contain the addresses observed in the created contract (either through storage or static analysis) as well as the machine learning score.
  - Finding type: Suspicious
  - Finding severity: High
  - Attack Stage: Preparation

## Test Data

The agent behaviour can be verified with the following transactions:

Ethereum Mainnet Transactions

- 0xcc915c5eece83e7c3d2d696a8893233b9da880716cb43d145dcab5c80344c741 (fake USDT erc20 Token - Fake_Phishing5959)
- 0x664b60a3b78d49a5d2787ef4ea7a599660777003404857da3b3e6c9f103c2ad1 (HydrogenBlue (HydroB) erc20 Token Phishing Scam - Fake_Phishing2600)
- 0x9b8e791189d4fb3a4b30066c8a8cdd625ef8830d942713ddf8c6221677220cf1 (Token impersonation of INVSBLE erc721 token by Invisible Friends- Fake_Phishing5349)
- 0x68d2f2a7fbdd6775c48ad010c7842f840012e9ac838b9d894e8188ae5c5401b1 (Bunny Buddies erc721 Token Phishing Scam - Fake_Phishing5328)




