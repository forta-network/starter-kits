# Ethereum Phishing Scam Detection ML Model

## Description

This bot utilizes the [EasyEnsembleClassifier](https://imbalanced-learn.org/stable/references/generated/imblearn.ensemble.EasyEnsembleClassifier.html) with [lightbgm classifiers](https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.LGBMClassifier.html#lightgbm.LGBMClassifier) to detect EOA phishing scammers. The model input data and algorithm was inspired by this paper: [Phishing Scam Detection on Ethereum: Towards Financial Security for
Blockchain Ecosystem](https://www.ijcai.org/proceedings/2020/0621.pdf)

### Machine Learning Model Description

```
EasyEnsembleClassifier(base_estimator=LGBMClassifier(learning_rate=0.02,
                                                     num_leaves=50,
                                                     random_state=42),
                       n_jobs=-1, random_state=42, sampling_strategy=0.01,
                       verbose=10)
```

EasyEnsemble is an ensemble of weak learners that uses undersampling to improve classification on imbalanced datasets. This works well for phishing scam detection because a very small percentage of addresses are scammers. I used LGB estimators for the weak learners. LGB, a distributed high-performance framework that uses decision tree.

<img src="./ensemble.png" alt="Ensemble of weak learners" width="400"/>

This machine learning model was trained to detect phishing scammers. The model outputs a prediction score between 0 and 1 (inclusive). Scores closer to 1 indicate that the address is most likely a phishing scammer. A threshold variable called `MODEL_THRESHOLD` is set to only consider alerting phishing scammers if the prediction score exceeds the specified threshold. If the threshold is exceeded, the analyzed address is considered a phishing scammer. The metadata will output model predictions as string labels `PHISHING_SCAMMER` and `NORMAL` for human readability.

The model detected 157 of **861** known scam addresses with `MODEL_THRESHOLD=0.5`, including 5 of the following known phishing scammer addresses:

* (DETECTED) [0x00000000e1a1a7883c90afc22f106f78084ebbfe](https://etherscan.io/address/0x00000000e1a1a7883c90afc22f106f78084ebbfe), # Fake_Phishing76195
* (DETECTED) [0x0000000dc3d9e17e3449e59bb75cb4005ee8aa7f](https://etherscan.io/address/0x0000000dc3d9e17e3449e59bb75cb4005ee8aa7f), # Fake_Phishing65917
* (DETECTED) [0x0000000f7e71bfbcdae6d29aa49ed557afaef9d2](https://etherscan.io/address/0x0000000f7e71bfbcdae6d29aa49ed557afaef9d2), # Fake_Phishing76593
* (DETECTED) [0x00c69f9421a1d58601a61275799cc2aeb443acc8](https://etherscan.io/address/0x00c69f9421a1d58601a61275799cc2aeb443acc8), # Fake_Phishing66311
* (DETECTED) [0xc6f5341d0cfea47660985b1245387ebc0dbb6a12](https://etherscan.io/address/0xc6f5341d0cfea47660985b1245387ebc0dbb6a12), # Fake_Phishing65972

**What features were used?**

* Addresses’ incoming and outgoing transaction count, blocknumber,  and value
* Addresses’ 1-degree neighbors’ transaction activity to identify money laundering and mass scamming activities.


<img src="./graph.png" alt="Graph of nodes" width="400"/>

**Metrics**

The model was evaluated against the test set from the [Kaggle competition](https://www.kaggle.com/competitions/forta-protect-web3/data):

* 131,277 non-scammers
* 443 known scammers
* Precision: `0.69`
* Recall: `0.44`
* F1-score: `0.54`

**ML Features**

* to_friends: EOAs’ first-degree neighbors who received a transaction from the EOAs
* from_friends: EOAs’ first-degree neighbors who sent a transaction to the EOAs

1. 'in_block_number_std': standard deviation of incoming transaction block number
2. 'from_address_nunique': unique number of from addresses
3. 'from_address_count_unique_ratio': unique # of from addresses / total # of from addresses
4. 'from_out_min_std': minimum of from friends' standard deviation outgoing transaction values
5. 'from_out_block_std_median': median of from friends'standard deviation of outgoing transaction block number
6. 'to_in_min_min': minimum of to friends' minimum incoming transaction value
7. 'to_in_sum_min': sum of to friends' minimum incoming transaction value
8. 'to_in_sum_median': sum of to friends' median incoming transaction value
9. 'to_in_block_std_median': median of to friends' std incoming block number
10. 'from_in_min_std': minimum of from friends' standard deviation of incoming transaction values
11. 'from_in_block_timespan_median': median of from friends' incoming transaction time spans
12. 'to_out_min_std': minimum of to friends' standard deviation of outgoing transaction values
13. 'total_time': last tx time - first tx time
14. 'in_ratio': minimum incoming eth / maximum incoming eth
15. 'ratio_from_address_nunique': unique # of from addresses / (total num transactions)
16. 'to_in_sum_median_ratio': 'to_in_sum_median' / total sum of incoming and outgoing value


## Supported Chains

- Ethereum

## Alerts

- EOA-PHISHING-SCAMMER
  - Fired when a from or to address from a transaction is identified as a phishing scammer.
  - Severity is always set to `CRITICAL`
  - Type is always set to `SUSPICIOUS`
  - Metadata includes model features and model prediction values. It also includes feature generation and prediction response times.


## Test Data

### Phishing Scammer Alert Example

```bash
$ npm run tx 0x76cbb86df35211d606df4f1abaaef10f908503dcf5e17b97569861714ddec319

1 findings for transaction 0x76cbb86df35211d606df4f1abaaef10f908503dcf5e17b97569861714ddec319 {
  "name": "Phishing Scammer Detected",
  "description": "0x0000000f7e71bfbcdae6d29aa49ed557afaef9d2 has been identified as a phishing scammer",
  "alertId": "EOA-PHISHING-SCAMMER",
  "protocol": "ethereum",
  "severity": "Critical",
  "type": "Suspicious",
  "metadata": {
    "scammer": "0x0000000f7e71bfbcdae6d29aa49ed557afaef9d2",
    "feature_generation_time": 1.13021675,
    "prediction_time": 2.705141125,
    "feature_0_eoa": "0x0000000f7e71bfbcdae6d29aa49ed557afaef9d2",
    "feature_1_from_address_count_unique_ratio": 0.9454545454545454,
    "feature_2_from_address_nunique": 52,
    "feature_3_in_block_number_std": 54089.239054963116,
    "feature_4_in_ratio": 0.00006925193467425777,
    "feature_5_ratio_from_address_nunique": 0.8253968253968254,
    "feature_6_total_time": 5009544,
    "feature_7_from_in_min_std": 0,
    "feature_8_from_in_block_timespan_median": 7899468,
    "feature_9_from_out_min_std": 0,
    "feature_10_from_out_block_std_median": 189179.11864268433,
    "feature_11_to_in_sum_min": 0.04000200000000074,
    "feature_12_to_in_sum_median": 0.5418970128273422,
    "feature_13_to_in_sum_median_ratio": 0.011575035930428634,
    "feature_14_to_in_min_min": 1e-18,
    "feature_15_to_in_block_std_median": 167757.5668731518,
    "feature_16_to_out_min_std": 1.4317874777547817,
    "anomaly_score": 1,
    "model_version": "1678286940",
    "model_threshold": 0.5
  },
  "addresses": [],
  "labels": [
    {
      "entityType": "Address",
      "entity": "0x0000000f7e71bfbcdae6d29aa49ed557afaef9d2",
      "label": "scammer-eoa",
      "confidence": 0.786,
      "remove": false,
      "metadata": {}
    }
  ]
}
```
