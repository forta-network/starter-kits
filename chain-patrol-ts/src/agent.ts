import { BlockEvent, Finding, Initialize, HandleBlock } from "forta-agent";
import { fetchApiKey, getDateFourWeeksAgoInYyyyMmDD, getCurrentDateInYyyyMmDD } from "./utils";
import { ApiKeys, Asset, AssetDetails, UnalertedAsset } from "./types";
import { createBlockedAssetFinding } from "./findings";
import AssetFetcher from "./fetcher";
import { ETHEREUM_BLOCKS_IN_ONE_DAY, MAX_ASSET_ALERTS_PER_BLOCK, ASSET_DETAILS_URL, ASSET_LIST_URL } from "./constants";

let hasCreatedAlertsUponDeployment: boolean;
let assetFetcher: AssetFetcher;
let assetListStartDate: string;

// Bots are allocated 1GB of memory, so storing
// `UnalertedAsset`s won't be an issue. Especially
// since entries will be cleared after alerted.
const unalertedAssets: UnalertedAsset[] = [];

async function createAssetFetcher(
  apiKey: string,
  assetListUrl: string,
  assetDetailsUrl: string
): Promise<AssetFetcher> {
  return new AssetFetcher(apiKey, assetListUrl, assetDetailsUrl);
}

export function provideInitialize(
  fetchApiKey: () => Promise<ApiKeys>,
  assetListUrl: string,
  assetDetailsUrl: string,
  createAssetFetcher: (apiKey: string, assetListUrl: string, assetDetailsUrl: string) => Promise<AssetFetcher>
): Initialize {
  return async () => {
    const {
      apiKeys: { CHAINPATROL: apiKey },
    } = await fetchApiKey();
    assetFetcher = await createAssetFetcher(apiKey, assetListUrl, assetDetailsUrl);
    assetListStartDate = getDateFourWeeksAgoInYyyyMmDD();
    hasCreatedAlertsUponDeployment = false;
  };
}

export function provideHandleBlock(): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    const findings: Finding[] = [];

    // Querying ChainPatrol API once per day,
    // otherwise API query returns zero results.
    // Argument format is `YYYY-MM-DD`
    if (blockEvent.blockNumber % ETHEREUM_BLOCKS_IN_ONE_DAY === 0 || !hasCreatedAlertsUponDeployment) {
      const currentDate = getCurrentDateInYyyyMmDD();
      const assetList: Asset[] | undefined = await assetFetcher.getAssetlist(currentDate, assetListStartDate);

      await Promise.all(
        assetList!.map(async (asset: Asset) => {
          const assetDetails: AssetDetails | undefined = await assetFetcher.getAssetDetails(asset.content);
          unalertedAssets.push({
            type: asset.type,
            status: asset.status,
            content: asset.content,
            updatedAt: asset.updatedAt,
            reason: assetDetails?.reason,
            reportId: assetDetails?.reportId,
            reportUrl: assetDetails?.reportUrl,
          });
        })
      );

      // `currentDate` will be used as `startDate`
      // for the next call to `getAssetList` in
      // the following day
      assetListStartDate = currentDate;

      if (!hasCreatedAlertsUponDeployment) {
        hasCreatedAlertsUponDeployment = true;
      }
    }

    const assetsToBeAlerted: UnalertedAsset[] = unalertedAssets.splice(
      0,
      Math.min(unalertedAssets.length, MAX_ASSET_ALERTS_PER_BLOCK)
    );

    findings.push(...assetsToBeAlerted.map(createBlockedAssetFinding));

    return findings;
  };
}

export default {
  initialize: provideInitialize(fetchApiKey, ASSET_LIST_URL, ASSET_DETAILS_URL, createAssetFetcher),
  handleBlock: provideHandleBlock(),
};
