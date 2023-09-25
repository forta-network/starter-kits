import { createAssetListApiOptions, createAssetDetailsApiOptions } from "./utils";
import { ApiOptions, AssetList, AssetDetails } from "./types";
import { ASSET_TYPES } from "./constants";

export default class AssetFetcher {
  assetListUrl: string;
  assetDetailsUrl: string;
  private apiKey: string;
  private readonly MAX_TRIES: number; // Retries counter

  constructor(apiKey: string, assetListUrl: string, assetDetailsUrl: string) {
    this.MAX_TRIES = 3;
    this.apiKey = apiKey;
    this.assetListUrl = assetListUrl;
    this.assetDetailsUrl = assetDetailsUrl;
  }

  getAssetlist = async (status: string, endDate: string, startDate: string): Promise<AssetList> => {
    // TODO: Add caching
    let tries = 0;

    let assetList: AssetList = { assets: [] };
    while (tries < this.MAX_TRIES) {
      try {
        // Since we can only query the API
        // with one `type` at a time
        const apiOptions: ApiOptions[] = [];
        ASSET_TYPES.map((type: string) => {
          apiOptions.push(createAssetListApiOptions(this.apiKey, type, status, endDate, startDate));
        });

        apiOptions.map(async (option: ApiOptions) => {
          const fetchedAssetList = (await (await fetch(this.assetListUrl, option)).json()) as AssetList;
          assetList.assets.push(...fetchedAssetList.assets);
        });
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
    return assetList;
  };

  getAssetDetails = async (assetContent: string): Promise<AssetDetails> => {
    // TODO: Add caching
    let tries = 0;

    let assetDetails: AssetDetails = {
      status: "",
      reason: "",
      reportId: 0,
      reportUrl: "",
    };
    while (tries < this.MAX_TRIES) {
      try {
        const options = createAssetDetailsApiOptions(this.apiKey, assetContent);
        assetDetails = (await (await fetch(this.assetDetailsUrl, options)).json()) as AssetDetails;
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
    return assetDetails;
  };
}
