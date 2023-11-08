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

> Note: `INIT_API_QUERY_DATE` in `src/constants.ts` should be updated as the desired `startDate` to be used to query [getAssetList](https://chainpatrol.io/docs/external-api/asset-list) upon the bot's initialization.

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

<img src="https://raw.githubusercontent.com/forta-network/starter-kits/tree/main/chain-patrol-ts/images/alert-findings.png" width="1134" height="741">

## 📜 License

The bot is released under the [Forta Bot License](https://github.com/NethermindEth/Forta-Agents/victim-loss-identifier/blob/main/LICENSE.md).