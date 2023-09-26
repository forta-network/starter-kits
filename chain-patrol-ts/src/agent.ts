import { BlockEvent, Finding, Initialize, HandleBlock } from "forta-agent";
import { fetchApiInfo, getCurrentDateInYyyyMmDD } from "./utils";
import { Asset, AssetDetails, UnalertedAsset } from "./types";
import { createBlockedAssetFinding } from "./findings";
import AssetFetcher from "./fetcher";
import {
  ETHEREUM_BLOCKS_IN_ONE_DAY,
  MAX_ASSET_ALERTS_PER_BLOCK,
  ASSET_BLOCKED_STATUS,
  INIT_API_QUERY_DATE,
  ASSET_DETAILS_URL,
  ASSET_LIST_URL,
} from "./constants";

let assetFetcher: AssetFetcher;
let apiQueryStartDate: string;

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
  fetchApiInfo: () => Promise<string>,
  assetListUrl: string,
  assetDetailsUrl: string,
  createAssetFetcher: (apiKey: string, assetListUrl: string, assetDetailsUrl: string) => Promise<AssetFetcher>,
  initApiQueryDate: string
): Initialize {
  return async () => {
    const apiKey = await fetchApiInfo();
    assetFetcher = await createAssetFetcher(apiKey, assetListUrl, assetDetailsUrl);
    apiQueryStartDate = initApiQueryDate;
  };
}

export function provideHandleBlock(getCurrentDateInYyyyMmDD: () => string): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    const findings: Finding[] = [];

    // Querying API once per day since the argument is `YYYY-MM-DD`,
    // and the day is the only way to distinguish one call from another
    if (blockEvent.blockNumber % ETHEREUM_BLOCKS_IN_ONE_DAY === 0) {
      const currentDate = getCurrentDateInYyyyMmDD();
      const assetList: Asset[] | undefined = await assetFetcher.getAssetlist(
        ASSET_BLOCKED_STATUS,
        currentDate,
        apiQueryStartDate
      );

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
  initialize: provideInitialize(
    fetchApiInfo,
    ASSET_LIST_URL,
    ASSET_DETAILS_URL,
    createAssetFetcher,
    INIT_API_QUERY_DATE
  ),
  handleBlock: provideHandleBlock(getCurrentDateInYyyyMmDD),
};
