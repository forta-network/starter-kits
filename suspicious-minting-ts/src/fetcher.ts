import { providers, Contract, BigNumber, ethers } from "ethers";
import LRU from "lru-cache";

type TokenPriceCacheEntry = {
  timestamp: number; // Timestamp when the cache entry was created
  value: number; // Cached value (USD price)
  decimals: number; // Cached decimals
};

export default class Fetcher {
  provider: providers.JsonRpcProvider;
  private tokensPriceCache: LRU<string, TokenPriceCacheEntry>;
  private priceCacheExpirationTime: number;
  private maxRetries: number;

  constructor(provider: ethers.providers.JsonRpcProvider) {
    this.provider = provider;
    this.tokensPriceCache = new LRU<string, TokenPriceCacheEntry>({
      max: 20000,
    });
    this.priceCacheExpirationTime = 6 * 60 * 60 * 1000; // 6 hours in milliseconds
    this.maxRetries = 2;
  }

  private getTokenPriceUrl = (chain: string, token: string) => {
    return `https://coins.llama.fi/prices/current/${chain}:${token}`;
  };

  private getChainByChainId = (chainId: number) => {
    switch (Number(chainId)) {
      case 10:
        return "optimism";
      case 56:
        return "bsc";
      case 137:
        return "polygon";
      case 250:
        return "fantom";
      case 42161:
        return "arbitrum";
      case 43114:
        return "avax";
      default:
        return "ethereum";
    }
  };

  private getNativeTokenByChainId = (chainId: number) => {
    switch (Number(chainId)) {
      case 10:
        return "ethereum";
      case 56:
        return "binancecoin";
      case 137:
        return "matic-network";
      case 250:
        return "fantom";
      case 42161:
        return "ethereum";
      case 43114:
        return "avalanche-2";
      default:
        return "ethereum";
    }
  };

  private getNativeTokenPrice = (chain: string) => {
    return `https://api.coingecko.com/api/v3/simple/price?ids=${chain}&vs_currencies=usd`;
  };

  public async getValueInUsd(
    chainId: number,
    amount: string,
    token: string
  ): Promise<number> {
    let response, usdPrice, decimals;
    let foundInCache = false;
    const key = `usdPrice-${token}`;

    if (this.tokensPriceCache.has(key)) {
      const cacheEntry = this.tokensPriceCache.get(key)!;

      if (cacheEntry.timestamp + this.priceCacheExpirationTime > Date.now()) {
        usdPrice = cacheEntry.value;
        decimals = cacheEntry.decimals;
        foundInCache = true;
      } else {
        // Cache entry has expired, remove it from the cache
        this.tokensPriceCache.delete(key);
      }
    }

    if (!foundInCache) {
      if (token === "native") {
        const chain = this.getNativeTokenByChainId(chainId);

        let retries = 3;
        while (retries > 0) {
          try {
            response = (await (
              await fetch(this.getNativeTokenPrice(chain))
            ).json()) as any;
            break;
          } catch {
            retries--;
          }
        }
        if (!response || !response[chain]) {
          return 0;
        } else {
          usdPrice = response[chain].usd;
          decimals = 18;
        }
      } else {
        const chain = this.getChainByChainId(chainId);
        for (let i = 0; i < this.maxRetries; i++) {
          try {
            response = (await (
              await fetch(this.getTokenPriceUrl(chain, token))
            ).json()) as any;

            if (
              response &&
              response["coins"][`${chain}:${token}`] &&
              response["coins"][`${chain}:${token}`]["confidence"] > 0.7
            ) {
              usdPrice = response["coins"][`${chain}:${token}`]["price"];
              decimals = response["coins"][`${chain}:${token}`]["decimals"];
              break;
            } else {
              throw new Error("Error: Can't fetch USD price on CoinGecko");
            }
          } catch {
            if (!response) {
              await new Promise((resolve) => setTimeout(resolve, 1000));
            } else {
              break;
            }
          }
        }
        if (!usdPrice) {
          return 0;
        }
      }

      const newCacheEntry = {
        timestamp: Date.now(),
        value: usdPrice,
        decimals: decimals,
      };
      this.tokensPriceCache.set(key, newCacheEntry);
    }

    let tokenAmount;
    if (token === "native") {
      tokenAmount = ethers.utils.formatEther(amount);
    } else {
      tokenAmount = ethers.utils.formatUnits(amount, decimals);
    }
    return Number(tokenAmount) * usdPrice;
  }
}
