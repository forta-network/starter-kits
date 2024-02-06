import { createRequire } from "module";
import { currencies, CurrencyAddress } from "../config/markets";

import type { TokenData, Market, Erc20Info, ApiKeys } from "../types/types.js";
import {
  Network as fortaNetwork,
  getEthersProvider,
  ethers,
  Log,
} from "forta-agent";
import { Network, Alchemy, NftTokenType, NftContract } from "alchemy-sdk";
import db from "../db";
import retry from "async-retry";
import { getErc20TokenPrice } from "../client";

interface SetTokenDataOpts {
  name?: string;
  tokens: { [key: string]: TokenData };
  tokenId: string;
  price?: number;
  priceInUsd?: number;
  amount?: number;
  market: Market;
  currencyAddr?: CurrencyAddress;
}

/**
 *
 * Format the price to four decimal places, or less if all trailing decimals are zeros.
 *
 * @function
 * @param {number} price - Price to format.
 * @returns {string} Price with up to four decimal places.
 **/
const formatPrice = (price: number): string => {
  let i = 0;
  let formatedPrice = price.toLocaleString("en-US", {
    minimumFractionDigits: 5,
    maximumFractionDigits: 5,
  });
  let lastIdx = formatedPrice.length - 1;

  while (formatedPrice[lastIdx] === "0" || formatedPrice[lastIdx] === ".") {
    i++;
    if (formatedPrice[lastIdx--] === ".") {
      break;
    }
  }

  if (i > 0) {
    formatedPrice = formatedPrice.slice(0, -i);
  }

  return formatedPrice === "" ? "0" : formatedPrice;
};

/**
 *
 * Sets the token data of a given token details.
 *
 * @function
 * @param {SetTokenDataOpts} opts - SetTokenDataOpts object.
 * @param {{[key: string]: TokenData}} opts.tokens - The token data object with token id as key.
 * @param {string} opts.tokenId - The token id.
 * @param {number} [opts.price=] - An optional nft sale price.
 * @param {number} [opts.amount=] - An optional token amount.
 * @param {Market} opts.market - The market object.
 * @param {CurrencyAddress} [opts.currencyAddr=] - An optional currency address.
 */
const setTokenData = (opts: SetTokenDataOpts): void => {
  const token = opts.tokens[opts.tokenId];
  const currency = opts.currencyAddr
    ? currencies[opts.currencyAddr]
    : undefined;

  if (token && token.markets) {
    const currentMarket = token.markets[opts.market.name];

    currentMarket.amount = opts.amount
      ? currentMarket.amount + opts.amount
      : currentMarket.amount;
    currentMarket.price.value = opts.price
      ? formatPrice(Number(currentMarket.price.value) + opts.price)
      : currentMarket.price.value;
  } else {
    opts.tokens[opts.tokenId] = {
      name: opts.name ? opts.name : "",
      tokenId: opts.tokenId,
      markets: {
        [opts.market.name]: {
          market: opts.market,
          amount: opts.amount ? opts.amount : 0,
          price: {
            value: opts.price ? formatPrice(opts.price) : "~",
            valueInUsd: opts.priceInUsd ? formatPrice(opts.priceInUsd) : "~",
            currency: {
              name: currency ? currency.name : "",
              decimals: currency ? currency.decimals : 0,
            },
          },
        },
      },
    };
  }
};

function extractNumericalValue(floorPriceDiff: string | undefined): number {
  if (!floorPriceDiff) {
    return 0;
  }

  const numericalValue = parseFloat(floorPriceDiff.replace("%", ""));
  return numericalValue;
}

function truncateDecimal(number: number): string {
  const decimalString = number.toFixed(20); // Convert number to a string with up to 20 decimals

  // Find the index of the last non-zero digit
  let lastIndex = decimalString.length - 1;
  while (lastIndex >= 0 && decimalString[lastIndex] === "0") {
    lastIndex--;
  }

  // Check if the last non-zero digit is a decimal point
  if (decimalString[lastIndex] === ".") {
    lastIndex--;
  }

  // Finding the index of the decimal point
  const decimalPointIndex = decimalString.indexOf(".");

  // Maximum number of decimal places to keep
  const maxDecimals = 4;

  // Finding the maximum index based on the number of significant decimal places
  const maxIndex = decimalPointIndex + maxDecimals;

  // Return the truncated string limited by the number of significant decimal places
  return decimalString.slice(0, Math.min(lastIndex + 1, maxIndex));
}

const getBatchContractData = async (
  contractAddresses: string[],
  apiKeys: ApiKeys,
  chainId?: number
): Promise<NftContract[]> => {
  // Alchemy sdk setup
  const settings = {
    apiKey: "",
    network: Network.ETH_MAINNET,
  };
  const { apiKeys: extractedApiKeys } = apiKeys;

  switch (chainId) {
    case 10:
      settings.apiKey = extractedApiKeys.ALCHEMY_OPT;
      settings.network = Network.OPT_MAINNET;
      break;
    case 137:
      settings.apiKey = extractedApiKeys.ALCHEMY_POLY;
      settings.network = Network.MATIC_MAINNET;
      break;
    case 42161:
      settings.apiKey = extractedApiKeys.ALCHEMY_ARB;
      settings.network = Network.ARB_MAINNET;
      break;
    default:
      settings.apiKey = extractedApiKeys.ALCHEMY_ETH;
      settings.network = Network.ETH_MAINNET;
      break;
  }

  const alchemy = new Alchemy(settings);

  const result = await retry(
    async () => {
      const response = await alchemy.nft.getContractMetadataBatch(
        contractAddresses
      );

      if (response === null) {
        console.log("Might hitting rate limit, try again", contractAddresses);
      }
      return response;
    },
    {
      retries: 5,
    }
  );
  return result;
};

const getBatchContractDataOnChain = async (
  contractAddresses: string[]
): Promise<NftContract[]> => {
  const NFT_CONTRACT_ABI = [
    "function name() view returns (string)",
    "function symbol() view returns (string)",
    "function supportsInterface(bytes4) view returns (bool)",
  ];

  const ERC721_INTERFACE_ID = "0x80ac58cd";
  const ERC1155_INTERFACE_ID = "0xd9b67a26";

  const provider = getEthersProvider();

  let data: NftContract[] = [];

  for (const address of contractAddresses) {
    const nftContract = new ethers.Contract(
      address,
      NFT_CONTRACT_ABI,
      provider
    );

    let isErc721, isErc1155;

    try {
      isErc721 = await nftContract.supportsInterface(ERC721_INTERFACE_ID);
    } catch (error) {
      isErc721 = false;
    }

    try {
      isErc1155 = await nftContract.supportsInterface(ERC1155_INTERFACE_ID);
    } catch (error) {
      isErc1155 = false;
    }

    if (isErc721 || isErc1155) {
      const [name, symbol] = await Promise.all([
        nftContract.name(),
        nftContract.symbol(),
      ]);
      data.push({
        name,
        symbol,
        tokenType: isErc721 ? NftTokenType.ERC721 : NftTokenType.ERC1155,
        address,
      });
    }
  }

  return data;
};

const calculateFloorPriceDiff = (
  avgItemPrice: number,
  floorPrice: number | null
): string => {
  console.log(`avgItemPrice: ${avgItemPrice}, floorPrice: ${floorPrice}`);
  if (floorPrice === null || floorPrice === 0) {
    return "UNKNOWN";
  }

  const floorPriceDiff = ((avgItemPrice - floorPrice) / floorPrice) * 100;
  console.log(`floorPriceDiff: ${floorPriceDiff}`);
  return `${floorPriceDiff >= 0 ? "+" : ""}${floorPriceDiff.toFixed(2)}%`;
};

function shortenAddress(address: string, digits = 4): string {
  if (!address) {
    throw new Error("Invalid address");
  }
  return `${address.slice(0, digits + 2)}...${address.slice(-digits)}`;
}

async function extractTransferInfo(
  log: Log,
  network: fortaNetwork,
  provider: ethers.providers.Provider
): Promise<Erc20Info | null> {
  const { address, topics, data } = log;

  if (currencies.hasOwnProperty(address)) {
    return null;
  }

  const defaultAbiCoder = new ethers.utils.AbiCoder();
  const sender = defaultAbiCoder.decode(["address"], topics[1]);
  const receiver = defaultAbiCoder.decode(["address"], topics[2]);
  let decimalData = parseInt(data, 16);

  const ERC20_ABI = [
    "function symbol() view returns (string)",
    "function decimals() view returns (uint8)",
  ];

  const erc20Contract = new ethers.Contract(address, ERC20_ABI, provider);

  if (decimalData && sender && receiver) {
    let symbol, decimals;
    try {
      [symbol, decimals] = await Promise.all([
        erc20Contract.symbol(),
        erc20Contract.decimals(),
      ]);
    } catch {
      return null;
    }

    decimalData = decimalData / 10 ** decimals;

    let usdPrice = (await getErc20TokenPrice(network, address)) ?? 0;
    console.log(`token: ${symbol} usd price: ${usdPrice}`);

    const transferInfo = {
      usdPrice: usdPrice,
      value: decimalData.toString(),
      name: symbol.toString(),
      decimals: decimals,
    };

    return transferInfo;
  }

  return null;
}

export {
  formatPrice,
  setTokenData,
  extractNumericalValue,
  truncateDecimal,
  getBatchContractData,
  getBatchContractDataOnChain,
  extractTransferInfo,
  calculateFloorPriceDiff,
  shortenAddress,
};
