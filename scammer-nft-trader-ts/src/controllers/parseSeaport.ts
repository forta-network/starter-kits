import { ethers } from "ethers";
import { formatPrice, setTokenData } from "../utils/helper";
import { markets, currencies } from "../config/markets";
import { parseNftTrader } from "./parseNftTrader";

import type { Log, Interface } from "ethers";

import type { ItemType, Market, TransactionData } from "../types";
import type { BigNumberish } from "ethers";
import { getErc20TokenPrice } from "../client";
import { Network } from "forta-agent";

export type OfferItem = {
  itemType: ItemType;
  token: string;
  identifier: string;
  amount: BigNumberish;
};

export type ConsiderationItem = {
  itemType: ItemType;
  token: string;
  identifier: string;
  amount: BigNumberish;
  recipient: string;
};

/**
 *
 * Parses the transaction log that interacts with Seaport contract
 * and updates the TransactionData object.
 *
 * @function
 * @param {TransactionData} tx - The transaction data object.
 * @param {Log} log - The transaction log object to be parsed.
 * @param {Market} market - The market object.
 **/
const parseSeaport = async (
  tx: TransactionData,
  log: any,
  market: Market,
  iface: Interface,
  network: Network
) => {
  let price;
  const token_id = {
    value: "",
  };

  const abiCoder = iface.getAbiCoder();
  const nullAddress = "0x0000000000000000000000000000000000000000";
  const decodedLogData = iface.parseLog({
    data: log.data,
    topics: [...log.topics],
  })?.args;

  if (!decodedLogData) {
    console.log("failed to decode log data:", tx.transactionHash);
    return;
  }
  const offer: OfferItem[] = decodedLogData.offer;
  const consideration: ConsiderationItem[] = decodedLogData.consideration;

  const isNftTrader = consideration.some((item: ConsiderationItem) => {
    const market = markets[item.recipient.toLowerCase()];

    if (market?.name === "nfttrader") {
      tx.interactedMarket = market;

      return true;
    }
  });

  console.log("isNftTrader:", isNftTrader);

  if (isNftTrader) return parseNftTrader(tx, log, decodedLogData, abiCoder);

  let nftOnConsiderationSide = false;
  const nftOnOfferSide = parse(offer, tx, market, token_id);

  if (!nftOnOfferSide)
    nftOnConsiderationSide = parse(consideration, tx, market, token_id);
  const token = tx.tokens[token_id.value];

  if (!nftOnOfferSide && !nftOnConsiderationSide) return;
  // if target nft on offer side, then consideration is the total price
  // else offer is the total price
  if (nftOnOfferSide) {
    const totalConsiderationAmount = consideration.reduce(getReducer(tx), 0);
    price = totalConsiderationAmount;
    tx.fromAddr =
      tx.fromAddr ?? abiCoder.decode(["address"], log.topics[1]).toString();
    if (decodedLogData.recipient !== nullAddress) {
      tx.toAddr = tx.toAddr ?? decodedLogData.recipient;
    }
  } else {
    const totalOfferAmount = offer.reduce(getReducer(tx), 0);
    price = totalOfferAmount;

    if (decodedLogData.recipient !== nullAddress) {
      tx.fromAddr = tx.fromAddr ?? decodedLogData.recipient;
    }
    tx.toAddr =
      tx.toAddr ?? abiCoder.decode(["address"], log.topics[1]).toString();
  }

  // Fix double counting sales price when seaport
  // using matchAdvancedOrders function.
  let doubleCounting = false;

  for (const tokenId in tx.tokens) {
    const _token = tx.tokens[tokenId];

    if (_token.markets) {
      const _opensea = _token.markets[market.name];

      if (_opensea.amount > 1 && tx.contractData.tokenType === "ERC721") {
        doubleCounting = true;
        tx.totalAmount -= _opensea.amount - 1;
        _opensea.amount = 1;
      }
    }
  }

  if (!doubleCounting && token.markets) {
    const opensea = token.markets[market.name];

    let tokenAddress =
      nftOnOfferSide && consideration.length > 0
        ? consideration[0].token
        : !nftOnOfferSide && offer.length > 0
        ? offer[0].token
        : "";

    const tokenPriceInUsd = tokenAddress
      ? await getErc20TokenPrice(network, tokenAddress)
      : 0;
    const usdValue = tokenPriceInUsd ? tokenPriceInUsd! * price : 0;

    opensea.price.valueInUsd =
      opensea.price.valueInUsd !== "~"
        ? formatPrice(Number(opensea.price.valueInUsd) + usdValue)
        : formatPrice(usdValue);
    opensea.price.value =
      opensea.price.value !== "~"
        ? formatPrice(Number(opensea.price.value) + price)
        : formatPrice(price);
    opensea.price.currency = tx.currency;
    tx.totalPrice += price;
    tx.totalPriceInUSD += usdValue;
  }
};

function isConsiderationItem(
  item: OfferItem | ConsiderationItem
): item is ConsiderationItem {
  return (item as ConsiderationItem).recipient !== undefined;
}

/**
 *
 * Creates a reducer function for calculating the total value of
 * token amounts in a transaction data object.
 *
 * @function
 * @param {TransactionData} tx - The transaction data object containing token amounts and their corresponding token symbols.
 * @returns {function(previous: number, current: OfferItem | ConsiderationItem): number}
 * A reducer function that takes in a previous total value and a current token item,
 * and returns the updated total value.
 **/
function getReducer(
  tx: TransactionData
): (previous: number, current: OfferItem | ConsiderationItem) => number {
  return (previous: number, current: OfferItem | ConsiderationItem) => {
    // console.log("Currency address", current.token.toLowerCase());
    // console.log("Currency amount", current.amount);
    const currency =
      currencies[current.token.toLowerCase() as keyof typeof currencies];

    if (
      isConsiderationItem(current) &&
      current.token.toLowerCase() === tx.contractAddress.toLowerCase()
    ) {
      tx.toAddr = current.recipient;
    }
    if (currency !== undefined) {
      tx.currency = currency;
      const result =
        previous +
        Number(ethers.formatUnits(current.amount, currency.decimals));

      return result;
    } else {
      return previous;
    }
  };
}

/**
 *
 * Parses an array of token items and updates a transaction data
 * object and a token ID object with relevant information.
 *
 * @function
 * @param {OfferItem[] | ConsiderationItem[]} items - An array of token items to be parsed.
 * @param {TransactionData} tx - The transaction data object to be updated with total amount and token data.
 * @param {Market} market - The market object containing market-specific data.
 * @param {{ value: string }} token_id - The token ID object to be updated with the parsed token ID.
 * @returns {boolean} - A boolean value indicating whether at least one item in the array corresponds to an NFT owned by the user.
 **/
const parse = (
  items: OfferItem[] | ConsiderationItem[],
  tx: TransactionData,
  market: Market,
  token_id: { value: string }
): boolean => {
  let isNft = false;

  for (const item of items) {
    if (item.token.toLowerCase() === tx.contractAddress) {
      const tokenId = item.identifier;
      const amount = Number(item.amount);

      token_id.value = tokenId;
      tx.totalAmount += amount;

      setTokenData({
        name: tx.contractData.name,
        tokens: tx.tokens,
        tokenId: String(tokenId).replace(/\D/g, ""),
        amount: amount,
        market: market,
      });

      isNft = true;
    }
  }
  return isNft;
};

export { parseSeaport };
