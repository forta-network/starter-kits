import { ApiOptions, AssetList, AssetDetails } from "./types";
import { ASSET_TYPES } from "./constants";
import { createAssetListApiOptions, createAssetDetailsApiOptions } from "./utils";

export default class AssetFetcher {
  assetListUrl: string;
  assetDetailsUrl: string;
  private apiKey: string;
  private readonly MAX_TRIES: number; // Retries counter

  constructor(apiKey: string, assetListUrl: string, assetDetailsUrl: string) {
    this.apiKey = apiKey;
    this.MAX_TRIES = 3;
    this.assetListUrl = assetListUrl;
    this.assetDetailsUrl = assetDetailsUrl;
  }

  getAssetlist = async (status: string, endDate: string, startDate: string): Promise<AssetList | undefined> => {
    // TODO: Add caching
    let tries = 0;

    while (tries < this.MAX_TRIES) {
      try {
        // Since we can only query the API
        // with one `type` at a time
        const apiOptions: ApiOptions[] = [];
        ASSET_TYPES.map((type: string) => {
          apiOptions.push(createAssetListApiOptions(this.apiKey, type, status, endDate, startDate));
        });

        let assetList: AssetList = { assets: [] };

        apiOptions.forEach(async (option: ApiOptions) => {
          const fetchedAssetList = (await (await fetch(this.assetListUrl, option)).json()) as AssetList;
          assetList.assets.push(...fetchedAssetList.assets);
        });
        return assetList;
      } catch (e) {
        tries++;
        console.log(`Error in fetching Asset List (attempt ${tries}): `, e);
        if (tries === this.MAX_TRIES) {
          throw e;
        }
      }
      // Wait for 1 second before retrying
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    return undefined;
  };

  getAssetDetails = async (assetContent: string): Promise<AssetDetails | undefined> => {
    // TODO: Add caching
    let tries = 0;

    while (tries < this.MAX_TRIES) {
      try {
        const options = createAssetDetailsApiOptions(this.apiKey, assetContent);
        const assetDetails = (await (await fetch(this.assetDetailsUrl, options)).json()) as AssetDetails;
        return assetDetails;
      } catch (e) {
        tries++;
        console.log(`Error in fetching Asset Details (attempt ${tries}): `, e);
        if (tries === this.MAX_TRIES) {
          throw e;
        }
      }
      // Wait for 1 second before retrying
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    return undefined;
  };
}
