import { ethers } from "ethers";
import { setTokenData } from "../utils/helper";
import { currencies, CurrencyAddress } from "../config/markets";

import type { Log, Interface } from "ethers";
import type { Market, TransactionData } from "../types";
import { Network } from "forta-agent";

/**
 *
 * Parses the transaction log for the looksrare market and
 * update transaction data with relevant information.
 *
 * @function
 * @param {TransactionData} tx - The transaction data object to be updated with total amount and token data.
 * @param {Log} log - The log event object containing information about the transaction.
 * @param {Market} market - The market object containing market-specific data.
 * @param {Interface} iface - The interface object containing the ABI for the market.
 **/
const parseLooksRare = (
  tx: TransactionData,
  log: any,
  market: Market,
  iface: Interface,
  network: Network
) => {
  const eventTypes = {
    "0x3ee3de4684413690dee6fff1a0a4f92916a1b97d1c5a83cdf24671844306b2e3":
      "takerBid",
    "0x68cd251d4d267c6e2034ff0088b990352b97b2002c0476587d0c4da889c11330":
      "takerAsk",
    "0x9aaa45d6db2ef74ead0751ea9113263d1dec1b50cea05f0ca2002cb8063564a4":
      "takerAsk",
  };

  /**
   * executeMultipleTakerBids
   * executeTakerBid
   */
  const abiCoder = iface.getAbiCoder();
  const eventType = eventTypes[log.topics[0] as keyof typeof eventTypes];
  const decodedLogData = iface.parseLog({
    data: log.data,
    topics: [...log.topics],
  })?.args;

  if (!decodedLogData) {
    console.log("failed to decode log data:", tx.transactionHash);
    return;
  }

  if (decodedLogData.collection.toLowerCase() !== tx.contractAddress) {
    return;
  }
  const currencyAddr =
    decodedLogData.currency.toLowerCase() as keyof typeof currencies;

  if (!currencyAddr) return;

  let priceRaw = decodedLogData.feeAmounts[0] + decodedLogData.feeAmounts[2];

  const price = Number(
    ethers.formatUnits(priceRaw, currencies[currencyAddr].decimals)
  );

  const tokenId = parseInt(decodedLogData.itemIds[0]);
  const amount = parseInt(decodedLogData.amounts[0]);
  const [from, to] = eventType === "takerBid" ? [2, 1] : [1, 2];
  if (eventType === "takerBid") {
    tx.toAddr = decodedLogData.bidRecipient.toString();
  } else if (eventType === "bidUser") {
    tx.toAddr = decodedLogData.bidRecipient.toString();
  }

  tx.fromAddr = decodedLogData.feeRecipients[0].toString();

  tx.totalPrice += price;
  tx.totalAmount += amount;

  setTokenData({
    tokens: tx.tokens,
    tokenId: String(tokenId),
    price: price,
    amount: amount,
    market: market,
    currencyAddr: currencyAddr,
  });
};

export { parseLooksRare };
