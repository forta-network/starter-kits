# Anomalous Transaction with Token Transfers

## Description

This bot utilizes machine learning to detect anomalous transactions with erc20 token transfers.

### Machine Learning Model Description

```
IsolationForest(random_state=42, n_estimators=100)
```

An [Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html#sklearn.ensemble.IsolationForest) model was trained to detect anomalous tx with erc20 token transfers. The model returns -1 for outliers and 1 for inliers, and the int values are mapped to string labels `ANOMALY` and `NORMAL` for human readability. The model considered 0.387% of the training dataset to be anomalous, including 4 of the following known exploit transactions:

* (DETECTED) '0x2b023d65485c4bb68d781960c2196588d03b871dc9eb1c054f596b7ca6f7da56', # SaddleFinance Exploit
* (DETECTED) '0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7', # Beanstalk Flashloan Exploit
* (DETECTED) '0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530', # FeiProtocol-Fuse Exploit
* (DETECTED) '0x958236266991bc3fe3b77feaacea120f172c0708ad01c7a715b255f218f9313c', # Inverse Finance Exploit 2
* '0x600373f67521324c8068cfd025f121a0843d57ec813411661b07edc5ff781842', # Inverse Finance Exploit 1
* '0xe0b0c2672b760bef4e2851e91c69c8c0ad135c6987bbf1f43f5846d89e691428', # Revest Finance Exploit

The model was trained on 14,469 transactions with the following 45 features:
```
MODEL_FEATURES = [
    'APE_transfers', # top 20 erc20 token transfer counts and values from txs on and after 12-01-21.
    'APE_value',
    'CRV_transfers',
    'CRV_value',
    'DAI_transfers',
    'DAI_value',
    'GALA_transfers',
    'GALA_value',
    'HEX_transfers',
    'HEX_value',
    'KOK_transfers',
    'KOK_value',
    'LINK_transfers',
    'LINK_value',
    'LOOKS_transfers',
    'LOOKS_value',
    'MANA_transfers',
    'MANA_value',
    'MATIC_transfers',
    'MATIC_value',
    'SAITAMA_transfers',
    'SAITAMA_value',
    'SAND_transfers',
    'SAND_value',
    'SHIB_transfers',
    'SHIB_value',
    'SOS_transfers',
    'SOS_value',
    'STRNGR_transfers',
    'STRNGR_value',
    'STRONG_transfers',
    'STRONG_value',
    'USDC_transfers',
    'USDC_value',
    'USDT_transfers',
    'USDT_value',
    'WBTC_transfers',
    'WBTC_value',
    'WETH_transfers',
    'WETH_value',
    'account_age_in_minutes', # diff between tx from address's first and tx that's being evaluated
    'max_single_token_transfers', # max token transfer count and value. Could be a token that's not in the top 20.
    'max_single_token_transfers_value',
    'tokens_type_counts', # unique number of token types transferred
    'transfer_counts' # total number of token transfer events
]
```

## Supported Chains

- Ethereum

## Alerts

- NORMAL-TOKEN-TRANSFERS-TX
  - Fired when a transaction is predicted as normal/inlier.
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata will include features and model prediction values. It will also include feature generation and prediction response times.
- ANOMALOUS-TOKEN-TRANSFERS-TX
  - Fired when a transaction is predicted as anomalous/outlier.
  - Severity is always set to "low" (mention any conditions where it could be something else)
  - Type is always set to "info" (mention any conditions where it could be something else)
  - Metadata will include features and model prediction values. It will also include feature generation and prediction response times.
- INVALID-TOKEN-TRANSFERS-TX
  - Fired when bot fails to generate valid model features. Model will not make predictions on invalid features.
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata will not include a model prediction.

## Test Data

### Normal Tx Example

```bash
$ npm run tx 0x404666af36d5f2e11f763391be0a5b40ae78dfd4304b4f22e3a53c369e779bf1

1 findings for transaction 0x404666af36d5f2e11f763391be0a5b40ae78dfd4304b4f22e3a53c369e779bf1 {
  "name": "Normal Transaction",
  "description": "0x1b4006139cfd127822ff9b26a0f89532977b3a42 executed normal tx with token transfers",
  "alertId": "NORMAL-TOKEN-TRANSFERS-TX",
  "protocol": "ethereum",
  "severity": "Info",
  "type": "Info",
  "metadata": {
    "from": "0x1b4006139cfd127822ff9b26a0f89532977b3a42",
    "transfer_counts": 1,
    "account_age_in_minutes": 0,
    "USDT_transfers": 1,
    "USDT_value": 1700,
    "token_types": [
      "Tether USD-USDT"
    ],
    "max_single_token_transfers_name": "Tether USD",
    "tokens_type_counts": 1,
    "max_single_token_transfers": 1,
    "max_single_token_transfers_value": 1700,
    "feature_generation_response_time": 3.8916723749999997,
    "model_prediction": "NORMAL",
    "model_score": 0.189,
    "model_pred_response_time": 0.019546082999999825
  },
  "addresses": []
}
```


### Anomalous Tx Example

```bash
$ npm run tx 0x2b023d65485c4bb68d781960c2196588d03b871dc9eb1c054f596b7ca6f7da56

1 findings for transaction 0x2b023d65485c4bb68d781960c2196588d03b871dc9eb1c054f596b7ca6f7da56 {
  "name": "Anomalous Transaction",
  "description": "0x63341ba917de90498f3903b199df5699b4a55ac0 executed anomalous tx with token transfers",
  "alertId": "ANOMALOUS-TOKEN-TRANSFERS-TX",
  "protocol": "ethereum",
  "severity": "Critical",
  "type": "Suspicious",
  "metadata": {
    "from": "0x63341ba917de90498f3903b199df5699b4a55ac0",
    "transfer_counts": 37,
    "account_age_in_minutes": 1.8333333333333333,
    "USDC_transfers": 8,
    "USDC_value": 80585621.27700001,
    "dUSDC_transfers": 2,
    "dUSDC_value": 0,
    "SUSD_transfers": 11,
    "SUSD_value": 149377797.167,
    "saddleUSD-V2_transfers": 10,
    "saddleUSD-V2_value": 67319643.022,
    "DAI_transfers": 2,
    "DAI_value": 3621446.912,
    "USDT_transfers": 2,
    "USDT_value": 3060977.952,
    "WETH_transfers": 2,
    "WETH_value": 6751.346,
    "token_types": [
      "Dai-DAI",
      "Euler Debt: USD Coin-dUSDC",
      "Saddle DAI/USDC/USDT V2-saddleUSD-V2",
      "Tether USD-USDT",
      "USD Coin-USDC",
      "WETH-WETH",
      "sUSD-SUSD"
    ],
    "max_single_token_transfers_name": "sUSD",
    "tokens_type_counts": 7,
    "max_single_token_transfers": 11,
    "max_single_token_transfers_value": 149377797.167,
    "feature_generation_response_time": 8.970852166,
    "model_prediction": "ANOMALY",
    "model_score": -0.165,
    "model_pred_response_time": 0.020986167000000222
  },
  "addresses": []
}
```
