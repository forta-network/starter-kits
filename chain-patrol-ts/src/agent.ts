import {
  BlockEvent,
  Finding,
  Initialize,
  HandleBlock,
  HandleTransaction,
  HandleAlert,
  AlertEvent,
  TransactionEvent,
  FindingSeverity,
  FindingType,
} from "forta-agent";
import AssetFetcher from "./fetcher";
import { fetchApiInfo, getCurrentDateInYyyyMmDD } from "./utils";
import { ASSET_LIST_URL, ASSET_DETAILS_URL, ETHEREUM_BLOCKS_IN_ONE_DAY } from "./constants";
import { ApiOptions, AssetList, Asset, AssetDetails } from "./types";
import { createFinding } from "./findings";

let assetFetcher: AssetFetcher;
// Will be used as the `startDate`
// next time when querying the API
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
  ) => Promise<AssetFetcher>
): Initialize {
  return async () => {
    assetFetcher = await assetFetcherCreator(apiFetcher, assetListUrl, assetDetailsUrl);
    // TODO: Set `lastFetchedDate` to however back we want to go the first
    // time we query the API
    // lastFetchedDate =
  };
}

export function provideHandleBlock(): HandleBlock {
  return async (blockEvent: BlockEvent): Promise<Finding[]> => {
    const findings: Finding[] = [];

    if (blockEvent.blockNumber % ETHEREUM_BLOCKS_IN_ONE_DAY === 0) {
      const currentDate = getCurrentDateInYyyyMmDD();
      const assetList: AssetList | undefined = await assetFetcher.getAssetlist("BLOCKED", currentDate, lastFetchedDate);

      if (assetList) {
        assetList.assets.map(async (asset: Asset) => {
          const assetDetails: AssetDetails | undefined = await assetFetcher.getAssetDetails(asset.content);
          if (assetDetails) {
            findings.push(createFinding(asset, assetDetails));
          }
        });
      }
    }

    return findings;
  };
}

export default {
  initialize: provideInitialize(fetchApiInfo, ASSET_LIST_URL, ASSET_DETAILS_URL, createNewAssetFetcher),
  handleBlock: provideHandleBlock(),
};
