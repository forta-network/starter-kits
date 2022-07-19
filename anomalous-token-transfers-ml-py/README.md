# Anomalous Transaction with Token Transfers

## Description

This bot utilizes the [Isolation Forest](https://scikit-learn.org/stable/modules/outlier_detection.html#isolation-forest) machine learning technique to detect anomalous transactions with erc20 token transfer. The Isolation Forest can efficiently detect outliers in high-dimensional datasets.

### Machine Learning Model Description

```
IsolationForest(random_state=42, n_estimators=100)
```

An [Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html#sklearn.ensemble.IsolationForest) model was trained to detect anomalous tx with erc20 token transfers. The model outputs an anomaly score that then gets normalized returning a score between 0 and 1 (inclusive). Scores closer to 1 are considered anomalies. A threshold variable called `ANOMALY_THRESHOLD` is set to only consider alerting anomalies if the score exceeds the specified threshold. If the threshold is exceeded, the tx is considered anomalous. If not, the tx is considered normal. The metadata will output model predictions as string labels `ANOMALY` and `NORMAL` for human readability.

The model considered 0.387% of the training dataset to be anomalous for `ANOMALY_THRESHOLD=0.5`, including 4 of the following known exploit transactions:

* (DETECTED) '0x2b023d65485c4bb68d781960c2196588d03b871dc9eb1c054f596b7ca6f7da56', # SaddleFinance Exploit
* (DETECTED) '0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7', # Beanstalk Flashloan Exploit
* (DETECTED) '0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530', # FeiProtocol-Fuse Exploit
* (DETECTED) '0x958236266991bc3fe3b77feaacea120f172c0708ad01c7a715b255f218f9313c', # Inverse Finance Exploit 2
* '0x600373f67521324c8068cfd025f121a0843d57ec813411661b07edc5ff781842', # Inverse Finance Exploit 1
* '0xe0b0c2672b760bef4e2851e91c69c8c0ad135c6987bbf1f43f5846d89e691428', # Revest Finance Exploit

The model was trained on 14,469 Ethereum mainnet transactions executed on and after 12-01-21.
The training dataset comprises 45 features for each transaction:
```
MODEL_FEATURES = [
    # First 40 features are selected erc20 token transfer counts and values in the tx that's being evaluated..
    # Top 20 tokens by number of token transfers on and after 12-01-21 were selected.
    'APE_transfers',
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
    'account_age_in_minutes', # diff between tx from address's first and tx that's being evaluated.
    'max_single_token_transfers', # max token transfer count and value. Could be a token that's not in the top 20.
    'max_single_token_transfers_value',
    'tokens_type_counts', # unique number of token types transferred.
    'transfer_counts' # total number of token transfer events in the tx that's being evaluated.
]
```

### When to update the ML model?

The model was trained on a sample of transactions executed between December - July 2022. As time passes, the model performance can degrade due to shifts in real world data distribution. In this case, the model can start considering more transactions as anomalous if the more recent transactions no longer share similar patterns or characteristics as the transactions the model was trained on. For example, drastic changes in majority transactions' token transfer count and value can affect the model to start considering normal transactions as anomalous.

Once the model is deployed, it's important to frequently monitor the anomaly rate to detect any deviations from the anomaly rate seen during training. If it deviates, it's recommended to retrain the model with new transaction data to learn the new 'normal' and 'anomalous' patterns.


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
    "feature_generation_response_time": 1.292835959,
    "prediction": "NORMAL",
    "anomaly_score": 0.311,
    "model_pred_response_time": 0.024292124999999887,
    "model_version": "1657669403",
    "anomaly_threshold": 0.5
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
    "feature_generation_response_time": 4.560809292,
    "prediction": "ANOMALY",
    "anomaly_score": 0.665,
    "model_pred_response_time": 0.023057041999999583,
    "model_version": "1657669403",
    "anomaly_threshold": 0.5
  },
  "addresses": []
}
```
