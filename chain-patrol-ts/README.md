# ChainPatrol Scam Detector

## ℹ️ Description

This bot supports the same scam detection functionality as the [ChainPatrol API](https://chainpatrol.io/docs/external-api/overview). It queries the `getAssetList` and `getAssetDetails` methods of the API, once per day, to detect new assets that have been declared a scam and subsequently given a status of `BLOCKED`. The bot then emits an alert containing information about said blocked assets.

## 🌐 Supported Chains

- Ethereum
  > Note: This bot is triggered by activity on Ethereum mainnet, specifically its blocks, but it is actually monitoring for offchain components, such as URLs and X/Twitter pages.

## 🚨 Alerts

### CHAINPATROL-SCAM-ASSET

- **Description**: Fired when an asset has been deemed a scam by ChainPatrol.
- **Severity**: Critical
- **Type**: Scam

**Metadata**:

- `type`: Type of asset. Either `URL`, `PAGE`, or `TWITTER`.
- `status`: Status of asset. Always set to `BLOCKED`.
- `updatedAt`: When asset was last updated, in ISO 8601 format.
- `reason`: Reason for result. Will either be "reported" if it was reported on ChainPatrol or "eth-phishing-detect" if it was reported on the eth-phishing-detect list.
- `reportId`: ID of report that caused latest asset status update.
- `reportUrl`: Link to report that caused latest asset status update.

**Labels**:

1. Asset
   - `entity`: Asset
   - `entityType`: URL
   - `label`: Either `Blocked URL`,  `Blocked PAGE`, or `Blocked TWITTER`.
   - `confidence`: 0.99

## 📊 Data Sources

- ChainPatrol (blocked assets)

## 🧪 Test Data

To verify the bot's behavior, you'll need to meet the following prerequisites.

1. Acquire a [ChainPatrol](https://chainpatrol.io/) API key and then create a `secrets.json` in the root directory of the bot like this:

```json
{
  "apiKeys": {
    "CHAINPATROL": "Your-ChainPatrol-API-Key"
  }
}
```

2. Create an `.env` file inthe root directory of the bot like this:

```
LOCAL_NODE = 1
```

You can verify the bot's behavior by following these steps:

1. Install the required dependencies:

```
npm install
```

2. Run the bot like this:

```
npm run start
```

The example alert after running the command:

```
{
  "name": "A scam has been detected by ChainPatrol",
  "description": "ChainPatrol detected scam: starksnet.life",
  "alertId": "CHAINPATROL-SCAM-ASSET",
  "protocol": "N/A",
  "severity": "Critical",
  "type": "Scam",
  "metadata": {
    "type": "URL",
    "status": "BLOCKED",
    "updatedAt": "2024-03-14T08:31:51.140Z",
    "reason": "reported",
    "reportId": "39169",
    "reportUrl": "https://app.chainpatrol.io/reports/39169",
    "Url": "starksnet.life"
  },
  "addresses": [],
  "labels": [
    {
      "entityType": "Url",
      "entity": "starksnet.life",
      "label": "Blocked URL",
      "confidence": 0.99,
      "remove": false,
      "metadata": {
        "type": "URL",
        "status": "BLOCKED",
        "updatedAt": "2024-03-14T08:31:51.140Z",
        "reason": "reported",
        "reportId": "39169",
        "reportUrl": "https://app.chainpatrol.io/reports/39169"
      }
    }
  ],
  "uniqueKey": "0xf8fe3c17500683400173ab9dfbaecee49850f3a5aff2a25a93a9aa40b16423b8",
  "source": {},
  "timestamp": "2024-04-12T19:53:22.000Z"
}
```

## 📜 License

The bot is released under the [Forta Bot License](https://github.com/NethermindEth/Forta-Agents/victim-loss-identifier/blob/main/LICENSE.md).