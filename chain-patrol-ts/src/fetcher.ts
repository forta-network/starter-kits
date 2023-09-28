import { LRUCache } from "lru-cache";
import { createAssetListApiOptions, createAssetDetailsApiOptions } from "./utils";
import { ApiOptions, AssetList, Asset, AssetDetails } from "./types";
import { ASSET_TYPES } from "./constants";

export default class AssetFetcher {
  assetListUrl: string;
  assetDetailsUrl: string;
  assetStatus: string;
  private apiKey: string;
  private readonly MAX_TRIES: number;
  private assetListCache: LRUCache<string, Asset[]>;
  private assetDetailsCache: LRUCache<string, AssetDetails>;

  constructor(apiKey: string, assetListUrl: string, assetDetailsUrl: string, assetStatus: string) {
    this.MAX_TRIES = 3;
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

  getAssetlist = async (endDate: string, startDate: string): Promise<Asset[] | undefined> => {
    const key = `${endDate}-${startDate}`;
    if (this.assetListCache.has(key)) {
      return this.assetListCache.get(key);
    }

    let tries = 0;
    while (tries < this.MAX_TRIES) {
      try {
        // Since we can only query the API
        // with one `type` at a time
        const apiOptions: ApiOptions[] = [];
        ASSET_TYPES.map((type: string) => {
          apiOptions.push(createAssetListApiOptions(this.apiKey, type, this.assetStatus, endDate, startDate));
        });

        let fetchedAssets: Asset[] = [];

        await Promise.all(
          apiOptions.map(async (options: ApiOptions) => {
            const fetchedAssetList = (await (await fetch(this.assetListUrl, options)).json()) as AssetList;
            fetchedAssets.push(...fetchedAssetList.assets);
          })
        );
        this.assetListCache.set(key, fetchedAssets);
        return fetchedAssets;
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
    if (this.assetDetailsCache.has(assetContent)) {
      return this.assetDetailsCache.get(assetContent);
    }

    let tries = 0;
    while (tries < this.MAX_TRIES) {
      try {
        const options = createAssetDetailsApiOptions(this.apiKey, assetContent);
        const assetDetails = (await (await fetch(this.assetDetailsUrl, options)).json()) as AssetDetails;
        this.assetDetailsCache.set(assetContent, assetDetails);
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
