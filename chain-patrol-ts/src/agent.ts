import { BlockEvent, Finding, Initialize, HandleBlock } from "forta-agent";
import { fetchApiInfo, getCurrentDateInYyyyMmDD } from "./utils";
import { AssetList, Asset, AssetDetails } from "./types";
import { createFinding } from "./findings";
import AssetFetcher from "./fetcher";
import {
  ASSET_LIST_URL,
  ASSET_DETAILS_URL,
  ASSET_BLOCKED_STATUS,
  INIT_API_QUERY_DATE,
  ETHEREUM_BLOCKS_IN_ONE_DAY,
} from "./constants";

let assetFetcher: AssetFetcher;
let lastFetchedDate: string;

async function createNewAssetFetcher(
  apiFetcher: () => Promise<string>,
  assetListUrl: string,
  assetDetailsUrl: string
): Promise<AssetFetcher> {
  const apiKey = await apiFetcher();
  return new AssetFetcher(apiKey, assetListUrl, assetDetailsUrl);
}

export function provideInitialize(
  apiFetcher: () => Promise<string>,
  assetListUrl: string,
  assetDetailsUrl: string,
  assetFetcherCreator: (
    apiFetcher: () => Promise<string>,
    assetListUrl: string,
    assetDetailsUrl: string
  ) => Promise<AssetFetcher>,
  initApiQueryDate: string
): Initialize {
  return async () => {
    assetFetcher = await assetFetcherCreator(apiFetcher, assetListUrl, assetDetailsUrl);
    lastFetchedDate = initApiQueryDate;
  };
}

export function provideHandleBlock(currentDateFetcher: () => string): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (blockEvent.blockNumber % ETHEREUM_BLOCKS_IN_ONE_DAY === 0) {
      const currentDate = currentDateFetcher();
      const assetList: AssetList = await assetFetcher.getAssetlist(ASSET_BLOCKED_STATUS, currentDate, lastFetchedDate);

      assetList.assets.map(async (asset: Asset) => {
        const assetDetails: AssetDetails = await assetFetcher.getAssetDetails(asset.content);
        if (assetDetails.reportId !== 0) {
          findings.push(createFinding(asset, assetDetails));
        }
      });
    }

    return findings;
  };
}

export default {
  initialize: provideInitialize(
    fetchApiInfo,
    ASSET_LIST_URL,
    ASSET_DETAILS_URL,
    createNewAssetFetcher,
    INIT_API_QUERY_DATE
  ),
  handleBlock: provideHandleBlock(getCurrentDateInYyyyMmDD),
};
