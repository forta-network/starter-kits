import { LRUCache } from "lru-cache";
import { createAssetListApiOptions, createAssetDetailsApiOptions } from "./utils";
import { ApiOptions, AssetList, Asset, AssetDetails } from "./types";
import { ASSET_TYPES, MAX_FETCH_ATTEMPTS } from "./constants";

export default class AssetFetcher {
  assetListUrl: string;
  assetDetailsUrl: string;
  assetStatus: string;
  private apiKey: string;
  private assetListCache: LRUCache<string, Asset[]>;
  private assetDetailsCache: LRUCache<string, AssetDetails>;

  constructor(apiKey: string, assetListUrl: string, assetDetailsUrl: string, assetStatus: string) {
    this.apiKey = apiKey;
    this.assetListUrl = assetListUrl;
    this.assetDetailsUrl = assetDetailsUrl;
    this.assetStatus = assetStatus;
    this.assetListCache = new LRUCache<string, Asset[]>({
      max: 1000,
    });
    this.assetDetailsCache = new LRUCache<string, AssetDetails>({
      max: 1000,
    });
  }

  private async fetchWithRetries(apiUrl: string, apiOptions: ApiOptions): Promise<any> {
    let tries = 0;
    while (tries < MAX_FETCH_ATTEMPTS) {
      try {
        return await fetch(apiUrl, apiOptions).then((response) => response.json());
      } catch (e) {
        tries++;
        console.log(`Error in fetching API data (attempt ${tries}): `, e);
        if (tries === MAX_FETCH_ATTEMPTS) {
          throw e;
        }
      }
      // Wait for 1 second before retrying
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    return undefined;
  }

  getAssetlist = async (endDate: string, startDate: string): Promise<Asset[] | undefined> => {
    const key = `${endDate}-${startDate}`;
    if (this.assetListCache.has(key)) {
      return this.assetListCache.get(key);
    }

    // Since we can only query the API
    // with one `type` at a time
    const apiOptionsList: ApiOptions[] = ASSET_TYPES.map((type: string) =>
      createAssetListApiOptions(this.apiKey, type, this.assetStatus, endDate, startDate)
    );

    const fetchedAssets: Asset[] = [];
    await Promise.all(
      apiOptionsList.map(async (options: ApiOptions) => {
        const fetchedAssetList = await this.fetchWithRetries(this.assetListUrl, options);
        fetchedAssets.push(...fetchedAssetList.assets);
      })
    );

    this.assetListCache.set(key, fetchedAssets);
    return fetchedAssets;
  };

  getAssetDetails = async (assetContent: string): Promise<AssetDetails | undefined> => {
    if (this.assetDetailsCache.has(assetContent)) {
      return this.assetDetailsCache.get(assetContent);
    }

    const options = createAssetDetailsApiOptions(this.apiKey, assetContent);
    const assetDetails = await this.fetchWithRetries(this.assetDetailsUrl, options);

    this.assetDetailsCache.set(assetContent, assetDetails);
    return assetDetails;
  };
}
