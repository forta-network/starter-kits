# Scam Detector Bot

## Description

The Scam Detector bot combines past alerts under a common address from a variety of underlying base bots to emit a high precision alert. It does so using a supervised machine learning model where alert counts for an EOA (or cluster) represents the feature vector. The model has been trained on 30 days of confirmed malicious accounts targeting end users (source through manual grading or known malicious address lists) and randomly sampled benign accounts. 

For example, a feature vector could look like:
EOA XYZ:
- 0xd9584a587a469f3cdd8a03ffccb14114bc78485657e28739b8036aee7782df5c, SEAPORT-PHISHING-TRANSFER: 4
- 0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14, ICE-PHISHING-HIGH-NUM-APPROVALS: 2
- 0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a, TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION: 1

The model emits a score along with the threshold that can further be used to tune recall/precision. Based on the test data, the current threshold of 0.50 maps to precison of 88% and threshold of 0.59 to a precision of 100%.

In addition, this model consumes manual lists for FP mitigation as well as crowdsourcing alerts from the Forta community.


## Supported Chains

- All Forta supported chains (note, it will appear that the bot only executes on one chain, but as it queries past Forta alerts, it essentially covers all chains)

## Alerts

The Scam Detector bot emits the following alerts:

- SCAM-DETECTOR-MODEL-1
  - Fires when the threshold is above 0.59.
  - Severity is set to critical
  - Type is always set to scam 
  - Meta data will contain examples of all the base bot alerts, the model score as well as the feature vector

- SCAM-DETECTOR-MODEL-2
  - Severity is set to low
  - Fires when the threshold is above 0.50-0.59.
  - Type is always set to scam
  - Meta data will contain examples of all the base bot alerts, the model score as well as the feature vector

- SCAM-DETECTOR-SIMILAR-1
  - Fires when new account deploys a contract that is similar to a previously alerted scammer 
  - Severity is set to critical
  - Type is always set to scam 
  - Meta data will contain information about the base bot

- SCAM-DETECTOR-MODEL-MANUAL-X
  - Fired for entries of the manual list maintained by the Forta community. X is replaced with the specific threat category. 
  - Severity is set to critical
  - Meta data will contain information about who reported the entry, a link to any public post, and the threat category.

- SCAM-DETECTOR-FALSE-POSITIVE
  - Fired when a false positive has been identified by the Forta community after an alert has been raised. 
  - Any labels emitted previously will be removed


The Scam Detector bot emits labels for each scammer address observed. 
```
    'entityType': EntityType.Address,
    'label': "scammer-eoa",
    'entity': address,
    'confidence': score,
    'metadata': {
      'alert_ids': comma separated list of alert_ids,
      'chain_id': chain_id,
      'threat_detection_urls': comma separated list pointing to a description of the threat category
    }
```

## Features/Base Bots Utilized By Scam Detector

- '0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef_AK-AZTEC-PROTOCOL-FUNDED-ACCOUNT-INTERACTION-0'
- '0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef_AK-AZTEC-PROTOCOL-FUNDING'
- '0x127e62dffbe1a9fa47448c29c3ef4e34f515745cb5df4d9324c2a0adae59eeef_count'
- '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_FLD_FUNDING'
- '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_FLD_Laundering'
- '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_FLD_NEW_FUNDING'
- '0x186f424224eac9f0dc178e32d1af7be39506333783eec9463edd247dc8df8058_count'
- '0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46_MALICIOUS-ACCOUNT-FUNDING'
- '0x2df302b07030b5ff8a17c91f36b08f9e2b1e54853094e2513f7cda734cf68a46_count'
- '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_ANOMALOUS-TOKEN-TRANSFERS-TX'
- '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_INVALID-TOKEN-TRANSFERS-TX'
- '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_NORMAL-TOKEN-TRANSFERS-TX'
- '0x2e51c6a89c2dccc16a813bb0c3bf3bbfe94414b6a0ea3fc650ad2a59e148f3c8_count'
- '0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba_SLEEPMINT-1'
- '0x33faef3222e700774af27d0b71076bfa26b8e7c841deb5fb10872a78d1883dba_count'
- '0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99_SUSPICIOUS-CONTRACT-CREATION'
- '0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99_count'
- '0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3_UNVERIFIED-CODE-CONTRACT-CREATION'
- '0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3_count'
- '0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a_TORNADO-CASH-FUNDED-ACCOUNT-INTERACTION'
- '0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a_count'
- '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_SAFE-TOKEN-CONTRACT-CREATION'
- '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_SUSPICIOUS-TOKEN-CONTRACT-CREATION'
- '0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad_count'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-APPROVAL-FOR-ALL'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC1155-APPROVAL-FOR-ALL-INFO'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC20-PERMIT'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC20-PERMIT-INFO'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-ERC721-APPROVAL-FOR-ALL-INFO'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVALS'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-APPROVED-TRANSFERS-LOW'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-HIGH-NUM-ERC20-APPROVALS-INFO'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-APPROVAL'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_ICE-PHISHING-SUSPICIOUS-TRANSFER'
- '0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14_count'
- '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e_FUNDING-CHANGENOW-LOW-AMOUNT'
- '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e_FUNDING-CHANGENOW-NEW-ACCOUNT'
- '0x9324d7865e1bcb933c19825be8482e995af75c9aeab7547631db4d2cd3522e0e_count'
- '0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c_SAFE-CONTRACT-CREATION'
- '0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c_SUSPICIOUS-CONTRACT-CREATION'
- '0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c_count'
- '0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b_MEV-ACCOUNT'
- '0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b_count'
- '0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb_LARGE-TRANSFER-OUT'
- '0xaf9ac4c204eabdd39e9b00f91c8383dc01ef1783e010763cad05cc39e82643bb_count'
- '0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_FLASHBOTS-TRANSACTIONS'
- '0xbc06a40c341aa1acc139c900fd1b7e3999d71b80c13a9dd50a369d8f923757f5_count'
- '0xdccd708fc89917168f3a793c605e837572c01a40289c063ea93c2b74182cd15f_AK-AZTEC-PROTOCOL-DEPOSIT-EVENT'
- '0xdccd708fc89917168f3a793c605e837572c01a40289c063ea93c2b74182cd15f_count'
- '0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_ASSET-DRAINED'
- '0xe4a8660b5d79c0c64ac6bfd3b9871b77c98eaaa464aa555c00635e9d8b33f77f_count'
- '0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb_CEX-FUNDING-1'
- '0xf496e3f522ec18ed9be97b815d94ef6a92215fc8e9a1a16338aee9603a5035fb_count'