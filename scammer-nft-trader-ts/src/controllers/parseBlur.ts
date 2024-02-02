import { ethers } from "ethers";
import { setTokenData } from "../utils/helper";
import type { Market, TransactionData } from "../types";
import { NftContract } from "alchemy-sdk";
import { Network } from "forta-agent";

const SafeCollectionBidPolicyERC721 =
  "0x0000000000b92d5d043faf7cecf7e2ee6aaed232";
// const StandardPolicyERC721 = '0x0000000000dab4a563819e8fd93dba3b25bc3495';

/**
 *
 * Parses the transaction log for the Blur market and update
 * transaction data object with relevant information.
 *
 * @function
 * @param {TransactionData} tx - The transaction data object to be updated.
 * @param {Log} log - The log event object containing information about the transaction.
 * @param {Market} market - The market object containing market-specific data.
 * @param {Interface} iface - The interface object for the market contract.
 * @param {NftContract} contractData - The contract data object for the market contract.
 **/
const parseBlur = (
  tx: TransactionData,
  log: any,
  market: Market,
  iface: ethers.Interface,
  contractData: NftContract,
  network: Network
) => {
  const decodedLogData = iface.parseLog({
    data: log.data,
    topics: [...log.topics],
  })?.args;

  if (!decodedLogData) {
    console.log("failed to decode log data:", tx.transactionHash);
    return null;
  }

  const tokenId = decodedLogData.sell.tokenId.toString();
  const amount = Number(decodedLogData.sell.amount);
  const price = Number(ethers.formatUnits(decodedLogData.sell.price, 18));
  const collection = decodedLogData.sell.collection.toLowerCase();
  const matchingPolicy = decodedLogData.sell.matchingPolicy.toLowerCase();

  if (matchingPolicy === SafeCollectionBidPolicyERC721) {
    tx.isBlurBid = true;
  }

  if (collection !== tx.contractAddress) {
    return;
  }

  tx.fromAddr = decodedLogData.sell.trader;
  tx.toAddr = decodedLogData.buy.trader;
  tx.totalPrice += price;
  tx.totalAmount += amount;

  setTokenData({
    name: contractData.name,
    tokens: tx.tokens,
    tokenId: tokenId,
    price: price,
    amount: amount,
    market: market,
    currencyAddr: "0x0000000000000000000000000000000000000000",
  });
};

export { parseBlur };
