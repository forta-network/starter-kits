# Early Attack Detector Documentation

## Description

The Early Attack Detector identifies smart contract exploits (protocol attacks) in real-time; before any digital assets are stolen. It does so by combining Machine Learning (ML) analysis of newly deployed smart contracts with funding analysis of the deployer address. This version of the attack detector focuses on the two initial attack stages (Funding and Preparation). By doing so, the Early Attack Detector can greatly improve its precision rate.

## Approach

This bot has two different thresholds (for each compatible chain, as of version 0.1.0 only eth). The high-precision threshold represents a risk score focused on very-high precision, and slightly lower recall (i.e., if the model thinks a smart contract is malicious, it's very likely to be malicious, but it may miss some smart contracts that are not so clear).

For a high-recall threshold, targeted more towards researchers and post-incident response, precision is slightly reduced in order to find as many malicious smart contracts as possible.

This bot only generates critical alerts. The logic behind these alerts is as follows:

1. Analyze all newly deployed smart contracts, and obtain a risk score from the ML model.
2. If the risk score reaches the high-precision threshold (for compatible chains), a high-precision flag is added to the metadata, and an alert is raised.
3. If the risk score reaches the high-recall threshold but under the high-precision thresholds, funding is checked. If the deployer address has received funding from low-KYC sources, a flag with the funding transaction is added to the metadata, and an alert is raised.
4. If the risk score is under both thresholds, no alert is raised.

## Alerts

- **EARLY-ATTACK-DETECTOR-1**, severity Critical. Alerts raised when the model is over the precision threshold and has been funded in the last 24 hours, or if the model precision is over the high precision threshold.
- **EARLY-AD-INFO**, [only for beta], severity Info. Auxiliary alerts for continuous improvement.

### Alert Schema

#### Querying the Early Attack Detector for alerts

```json
{
  "data": {
    "alerts": {
      "alerts": [
        {
          "alertId": "EARLY-AD-INFO",
          "addresses": [
            "0x40e7399c3cca782a7452dd158bfae9dae555936c",
            "0x34c36d6382fbf7885da6c46eaeb96a5a41f23ce8"
          ],
          "contracts": [
            {
              "address": "0x40e7399c3cca782a7452dd158bfae9dae555936c"
            },
            {
              "address": "0x34c36d6382fbf7885da6c46eaeb96a5a41f23ce8"
            }
          ],
          "createdAt": "2024-03-18T06:03:48.849788734Z",
          "description": "0x40e7399c3cca782a7452dd158bfae9dae555936c created contract 0x34C36d6382FbF7885da6C46eAeB96a5A41F23CE8",
          "metadata": {
            "functionSignatures": "",
            "fundingAlerts": "0x7abb486d17dd2697f7c43b6855c6166c9e521dac9855297d890725f9b7e845f8",
            "fundingLabels": "0xe5a71c6bbb2c806fb2906b06d620b046f913f81be66e44174f86b9ad5289ec11",
            "modelScore": "0.5107",
            "modelThreshold": "0.57",
            "okoContractExplorer": "https://oko.palkeo.com/0x34C36d6382FbF7885da6C46eAeB96a5A41F23CE8/"
          },
          "severity": "INFO",
          "source": {
            "transactionHash": "0xdfe85147cbd66f0f7c7a03621d3de5b881ede128cf29a0eaa20b6078dd2bb408",
            "bot": {
              "chainIds": null
            }
          }
        }
      ]
    }
  }
}
```

#### Metadata

The metadata for each alert will contain the following fields:

- function_signatures: All the possible function signatures
- high_precision_model: [optional] In case when the model was triggered due to the high precision model, a flag showing true.
- funding_alerts: [optional] When there are potential fundings, the hash(es) to the funding alert(s)
- funding_labels: [optional] When there are potential fundings, the hash(es) to the funding label(s)
- model_score: Model score. In case where the alert was raised due to the high precision model, the score will be from the high precision model.
- model_threshold: Recall threshold that was being used in the model at the moment of raising the alert
- known_past_attacker: [optional] When the transaction initiator is found to be a known past attacker, (i.e. associated with a public disclosed attack in the past) this value will be set to `"True"`.
- oko_contract_explorer: Link to contract explorer

Example of high precision model:

```json
{
  "function_signatures": "0x57ea89b6,0x2b42b941,0xe2d73ccd,0xeaf67ab9,0xf39d8c65,0x9763d29b,0xbedf0f4a,0xe26d7a70,0xffffffff",
  "high_precision_model": "true",
  "model_score": "0.7028",
  "model_threshold": "0.52",
  "oko_contract_explorer": "https://oko.palkeo.com/0x43421e5f28fb0650f736d917541265fd7a6b69a0/"
}
```

Example of alert with labels:

```json
{
  "function_signatures": "",
  "funding_alerts": "0x7abb486d17dd2697f7c43b6855c6166c9e521dac9855297d890725f9b7e845f8",
  "funding_labels": "0xe5a71c6bbb2c806fb2906b06d620b046f913f81be66e44174f86b9ad5289ec11",
  "model_score": "0.5107",
  "model_threshold": "0.57",
  "oko_contract_explorer": "https://oko.palkeo.com/0x34C36d6382FbF7885da6C46eAeB96a5A41F23CE8/"
}
```

In the second example, we can see that model_score is smaller than model_threshold. This can only happen in `EARLY-AD-INFO`, and it is used for improvement of the underlying ML models.

#### Querying the Early Attack Detector for labels

```json
 "data": {
    "labels": {
      "labels": [
        {
          "id": "0xe55b4abbf6fea34b6749f7c3507485e722dc0fbcb131eb00386d7a95da8c4b9c",
          "label": {
            "label": "contract",
            "entity": "0x39353dC161d5b0913facE276F83d72910Be6f1e3",
            "entityType": "ADDRESS",
            "metadata": null
          },
          "source": {
            "bot": {
              "id": "0xf60b23986fc15a8ff9bc78cc47daeb13a1bef4bfc3d867f3425b355f750866a7"
            },
            "alertHash": "0x672495f9998f829f4bcaf7df4494b5c40a72d6401cd73fe3681d268e7e055648",
            "alertId": "EARLY-ATTACK-DETECTOR-1",
            "chainId": 56
          }
        }
      ]
    }
 }

```

## Metrics

Metrics are calculated using a 5-fold CV fashion (Divide data in 5 splits, train 4 of them, predict on the unseen 5th, then calculate metrics over the whole dataset).

| version | eth f1 | eth p | eth r | oc f1 | oc p | oc r | ehp f1 | ehp p | ehp r | ochp f1 | ochp p | ochp r |
| :-----: | :----: | :---: | :---: | :---: | :--: | :--: | :----: | :---: | :---: | :-----: | :----: | :----: |
| v0.2.0  |  0.47  | 0.32  | 0.92  | 0.38  | 0.24 | 0.9  |  0.48  | 0.99  | 0.31  |  0.26   |  0.96  |  0.15  |
| v0.1.0  |  0.47  | 0.32  | 0.92  | 0.38  | 0.24 | 0.9  | 0.184  | 0.93  |  0.1  |    -    |   -    |   -    |
| v0.0.1  |  0.54  | 0.39  |  0.9  | 0.36  | 0.23 | 0.89 |  0.78  | 0.89  | 0.69  |  0.26   |  0.84  |  0.15  |

Legend:

- oc - other chains
- p - precision
- r - recall
- ehp - eth high precision
- ochp - other chains high precision

## Integrations

### Testing via the GraphQL API

The Early Attack Detector produces alers and labels which are available via Forta's GraphQL API. The GraphQL API provides for incredible flexibility and customization for your specific use cases. For accessing threat intel from the Early Attack Detector, we recommend querying for alerts generated by this bot (bots parameter needs to be set to ["0xf60b23986fc15a8ff9bc78cc47daeb13a1bef4bfc3d867f3425b355f750866a7"].)

Your API key will be required. You can go [HERE](https://docs.forta.network/en/latest/api-keys/?_gl=1*1ss8ki4*_ga*Njg5MDIxNjQ5LjE2ODU5OTEyODE.*_ga_3ERDDVRGQQ*MTcxMDc5MDk3NS4xNjIuMS4xNzEwNzkxODQzLjAuMC4w) for an explanation on how to generate your API key.

Click [HERE](https://docs.forta.network/en/latest/forta-api-reference/?_gl=1*zxaxka*_ga*Njg5MDIxNjQ5LjE2ODU5OTEyODE.*_ga_3ERDDVRGQQ*MTcxMDc5MDk3NS4xNjIuMS4xNzEwNzkyMDMzLjAuMC4w#query-labels) for a complete reference to the Forta GraphQL API parameters.

### Openzeppelin Defender

The OpenZeppelin Defender platform is a developer security platform that allows you to audit, deploy and monitor blockchain applications. Within Defender, you can easily and quickly begin utilizing the Attack Detector in order to protect your protocol’s smart contracts. Defender can take action of the Attack Detector’s alerts automatically pausing the protocol preventing loss of funds. Please visit the OpenZeppelin Defender docs [here](https://docs.openzeppelin.com/defender) regarding any questions about how to use Defender.
