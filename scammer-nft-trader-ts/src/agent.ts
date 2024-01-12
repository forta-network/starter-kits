import {
  Finding,
  TransactionEvent,
  FindingType,
  EntityType,
  Label,
  FindingSeverity,
  getEthersProvider,
} from "forta-agent";
import { createCustomAlert } from "./utils/alerts";
import db from "./db";
import {
  addTransactionRecord,
  getLatestTransactionRecords,
  getNativeTokenPrice,
  getErc20TokenPrice,
  getOpenSeaFloorData,
} from "./client";

import { transferEventTopics } from "./config/logEventTypes";
import type { NftContract } from "alchemy-sdk";
import { transferIndexer } from "./controllers/parseTx.js";

import type {
  TransactionRecord,
  TransactionData,
  TokenInfo,
  Erc20Info,
  ApiKeys,
} from "./types/types.js";
import { markets } from "./config/markets";
import { getCurrentTimestamp } from "./utils/tests";
import { round } from "lodash";
import {
  calculateFloorPriceDiff,
  extractNumericalValue,
  extractTransferInfo,
  getBatchContractData,
  getBatchContractDataOnChain,
  shortenAddress,
  truncateDecimal,
} from "./utils/helper";
import { FLOOR_PRICE_CURRENCIES, STABLECOINS } from "./utils/constants";
import { getSecrets } from "./storage";

const alchemySupportedChains = [1, 137, 42161];

let nftContractsData: NftContract[] = [];
let chainCurrency: string = "ETH";
let apiKeys: ApiKeys;

/**	
  Phishers/scammers that steal NFTs eventually need to sell them.
  This bot should identify NFT traders.
  Scammers vs legitimate users can probably be distinguished by how quickly they 
  sell an NFT they obtained as well as how close/below of the floor price they are.
  At the moment the bot indexes all the NFTS that are traded on the following markets:
  - Opensea
  - Blur
  - LooksRare
  We want to save this information to the database.
*/

export const initialize = async () => {
  apiKeys = (await getSecrets()) as ApiKeys;
};

export const provideHandleTransaction =
  (getOpenSeaFloorData: any) =>
  async (txEvent: TransactionEvent, testAPI?: NftContract[]) => {
    const network = txEvent.network;
    const findings: Finding[] = [];
    const extraERC20: Erc20Info[] = [];
    let currencyType;

    const MIN_USD_VALUE = 50; // Min USD value to be considered for phishing

    const isNftRelated = txEvent.logs.some((log) =>
      [transferEventTopics.ERC721, ...transferEventTopics.ERC1155].includes(
        log.topics[0]
      )
    );

    // Filter undefined values
    const filteredAddresses = Object.fromEntries(
      Object.entries(txEvent.addresses).filter(
        ([key, _]) => key !== "undefined"
      )
    );
    if (
      !Object.keys(markets).some((key) =>
        filteredAddresses.hasOwnProperty(key)
      ) ||
      !isNftRelated
    ) {
      return findings;
    }
    console.log(
      `*** ${txEvent.hash} is agent related in network ${network} ***`
    );

    const nativeTokenPrice = testAPI ? 777 : await getNativeTokenPrice(network);

    const provider = getEthersProvider();
    const chainId = (await provider.getNetwork()).chainId;

    for (const log of txEvent.logs) {
      if (log.topics.includes(transferEventTopics.ERC20)) {
        let res = await extractTransferInfo(log, network, provider);
        if (res) extraERC20.push(res);
      }
    }

    // get all the information for the contracts
    if (!testAPI) {
      if (alchemySupportedChains.includes(chainId)) {
        nftContractsData = await getBatchContractData(
          Object.keys(filteredAddresses),
          apiKeys,
          chainId
        );
      } else {
        console.log("Using on-chain data for chainId: ", chainId, "...");
        nftContractsData = await getBatchContractDataOnChain(
          Object.keys(filteredAddresses)
        );
      }
      chainCurrency =
        chainId === 56
          ? "BNB"
          : chainId === 137
          ? "MATIC"
          : chainId === 43114
          ? "AVAX"
          : "ETH";
    } else {
      console.log("Test Data Loaded");
      nftContractsData = testAPI;
    }

    for (const info of nftContractsData) {
      try {
        if (Object.keys(info).length !== 0) {
          if (
            ((!alchemySupportedChains.includes(chainId) ||
              Number(info.totalSupply) > 1) && // Total supply is 1 in cases of implementation contracts (fetched only on chains supported by Alchemy)
              info.tokenType === "ERC721") ||
            info.tokenType === "ERC1155"
          ) {
            const isNftTransferredFromInitiator = txEvent.logs.some(
              (log, index, logsArray) =>
                [
                  transferEventTopics.ERC721,
                  ...transferEventTopics.ERC1155,
                ].includes(log.topics[0]) &&
                nftContractsData.some(
                  (info) =>
                    (info.tokenType === "ERC721" ||
                      info.tokenType === "ERC1155") &&
                    log.address.toLowerCase() === info.address.toLowerCase() &&
                    (info.tokenType === "ERC1155"
                      ? "0x" + log.topics[2].toLowerCase().slice(26) ===
                        txEvent.from.toLowerCase()
                      : "0x" + log.topics[1].toLowerCase().slice(26) ===
                        txEvent.from.toLowerCase())
                ) &&
                !logsArray.some(
                  (otherLog, otherIndex) =>
                    index !== otherIndex &&
                    [
                      transferEventTopics.ERC721,
                      ...transferEventTopics.ERC1155,
                    ].includes(otherLog.topics[0]) &&
                    log.address.toLowerCase() ===
                      otherLog.address.toLowerCase() &&
                    (nftContractsData.find(
                      (info) =>
                        info.address.toLowerCase() === log.address.toLowerCase()
                    )?.tokenType === "ERC1155"
                      ? log.data === otherLog.data
                      : log.topics[3] === otherLog.topics[3])
                )
            );

            if (isNftTransferredFromInitiator) return findings;

            console.log(
              `run indexer for ${info.name} ${info.address} ${txEvent.hash}`
            );
            const find: TransactionData | undefined = await transferIndexer(
              txEvent,
              info
            );

            if (!find) return findings;

            let floorPriceUSD: number = 0;
            let record: TransactionRecord;
            let _avgItemPrice =
              find.totalPrice / Object.keys(find.tokens).length;
            let _floorPrice = find.contractData.openSea?.floorPrice || 0;

            let {
              floorPrice: directFloorPrice,
              currency,
              numberOfOwners,
              totalSales,
              totalVolume,
            } = await getOpenSeaFloorData(
              find.contractAddress,
              apiKeys.apiKeys.OPENSEA,
              chainId
            );
            console.log(`Alchemy Direct Floor Price: ${_floorPrice}`);

            if (
              !numberOfOwners ||
              numberOfOwners < 50 ||
              !totalSales ||
              !totalVolume ||
              totalVolume < 2
            ) {
              return findings;
            }

            // if direct floor price is not null compare against _floorPrice and set _floorPrice to the min of the two
            if (directFloorPrice !== null) {
              if (currency && ["WETH", "ETH"].includes(currency)) {
                _floorPrice =
                  _floorPrice == 0
                    ? directFloorPrice
                    : Math.min(_floorPrice, directFloorPrice);
              } else {
                _floorPrice = directFloorPrice;
              }
            }

            if (currency && FLOOR_PRICE_CURRENCIES[currency]) {
              const floorPriceTokenPrice = await getErc20TokenPrice(
                FLOOR_PRICE_CURRENCIES[currency].network,
                FLOOR_PRICE_CURRENCIES[currency].tokenAddress
              );
              floorPriceUSD = _floorPrice * floorPriceTokenPrice!;
            }

            if (!floorPriceUSD) {
              floorPriceUSD =
                currency && directFloorPrice && STABLECOINS.includes(currency)
                  ? directFloorPrice
                  : nativeTokenPrice
                  ? _floorPrice * nativeTokenPrice
                  : 0;
            }

            console.log(`floorPriceUSD: ${floorPriceUSD}`);
            record = {
              interactedMarket: find.interactedMarket.name,
              transactionHash: find.transactionHash,
              toAddr: find.toAddr?.toLowerCase(),
              fromAddr: find.fromAddr?.toLowerCase(),
              initiator: !testAPI ? txEvent.from : find.fromAddr,
              totalPrice: find.totalPrice,
              totalPriceInUSD: find.totalPriceInUSD,
              avgItemPrice: _avgItemPrice,
              contractAddress: find.contractAddress,
              floorPrice: _floorPrice,
              currency: currency!,
              timestamp: !testAPI ? txEvent.timestamp : getCurrentTimestamp(),
              tokens: {},
              floorPriceDiff: "",
            };

            // iterate over the tokens of find
            for (const token of Object.keys(find.tokens)) {
              const market =
                find.tokens[token].markets?.[find.interactedMarket.name];
              const marketPrice = market
                ? market.price.value === "~"
                  ? { value: "0", currency: { name: "ETH", decimals: 18 } }
                  : market.price
                : { value: "0", currency: { name: "ERR", decimals: 0 } };

              record.tokens[token] = {
                name: find.tokens[token].name || info.name!,
                price: marketPrice,
              };
            }

            console.log("extraERC20", JSON.stringify(extraERC20));

            const sumValues: { [name: string]: number } = {};

            const key = Object.keys(record.tokens)[0];
            let nativeERC20value: number = 0;
            let ercToNativeMSG: string = ``;

            // ASUME ONLY ONE ERC20 TOKEN
            if (extraERC20.length > 0) {
              const tokenName = extraERC20[0].name;

              for (const extraToken of extraERC20) {
                const value = Number(extraToken.value);
                sumValues[tokenName] = (sumValues[tokenName] || 0) + value;
              }

              record.tokens[key].price = {
                value: String(sumValues[tokenName]),
                currency: {
                  name: tokenName,
                  decimals: extraERC20[0].decimals,
                },
              };

              currencyType = tokenName;
              if (record.avgItemPrice == 0) {
                let avgItemPriceSum: number = 0;
                for (const key in record.tokens) {
                  if (
                    Object.prototype.hasOwnProperty.call(record.tokens, key)
                  ) {
                    const tokenInfo: TokenInfo = record.tokens[key];
                    avgItemPriceSum += Number(tokenInfo.price.value);
                  }
                }
                record.avgItemPrice = Number(
                  (avgItemPriceSum / Object.keys(record.tokens).length).toFixed(
                    2
                  )
                );
                record.totalPrice = avgItemPriceSum;

                record.avgItemPrice = round(record.avgItemPrice, 2);
                record.totalPrice = round(record.totalPrice, 2);
              }

              if (nativeTokenPrice) {
                nativeERC20value = Number(
                  truncateDecimal(
                    (Number(sumValues[tokenName]) *
                      Number(extraERC20[0].usdPrice)) /
                      nativeTokenPrice
                  )
                );
                ercToNativeMSG = `(~${nativeERC20value} ${chainCurrency})`;
                console.log(
                  `1 ${chainCurrency} = ${nativeTokenPrice} | 1 ${tokenName} => ${extraERC20[0].usdPrice} | ${sumValues[tokenName]} ${tokenName} = ${nativeERC20value} ${chainCurrency} ${ercToNativeMSG}`
                );
                record.avgItemPrice = nativeERC20value;
                record.totalPrice = nativeERC20value;
              }
            }

            if (record.totalPriceInUSD != 0) {
              // Seaport (Tentative)
              const _avgItemPriceUsd =
                find.totalPriceInUSD / Object.keys(find.tokens).length;

              record.floorPriceDiff = calculateFloorPriceDiff(
                _avgItemPriceUsd,
                floorPriceUSD
              );
            } else {
              record.floorPriceDiff = calculateFloorPriceDiff(
                record.avgItemPrice,
                _floorPrice
              );
            }

            console.log("[record status]", record ? "found" : "not found");

            try {
              await addTransactionRecord(db, record);
            } catch {
              console.log("Error inserting transaction record");
            }

            // await getTransactionByHash(db, txEvent.hash);

            const tokenId = Object.keys(find.tokens)[0];

            let records: any = await getLatestTransactionRecords(
              db,
              find.contractAddress,
              tokenId
            );

            console.log(
              "[record by id status]",
              records ? `found (${records.length})` : "err"
            );
            let global_name =
              record.tokens[tokenId]?.name ?? record.contractAddress;

            if (records.length > 1) {
              // compare the timestamp of the last two records and save the result in minutes
              // Calculate the time difference in minutes
              const timeDifferenceMinutes = (
                (records[0].transaction.timestamp -
                  records[1].transaction.timestamp) /
                60
              ).toFixed(2);

              // Calculate the average item price difference
              const avgItemPriceDifference =
                records[0].transaction.avg_item_price -
                records[1].transaction.avg_item_price;

              // Calculate the profit/loss percentage
              const floorPriceDiffs = records
                .slice(0, 2)
                .reduce((acc: any, record: any, index: number) => {
                  const key = index === 0 ? "current sale" : "last sale";
                  acc[key] = {
                    timestamp: record.transaction.timestamp,
                    floorPriceDiff: record.transaction.floor_price_diff,
                    avgItemPrice: record.transaction.avg_item_price,
                  };
                  return acc;
                }, {});

              // Check if the to_address of the oldest record matches the from_address of the newest record
              const addressMatch =
                records[0].transaction.from_address ===
                records[1].transaction.to_address;

              console.log("----- addressMatch -----", addressMatch);
              if (addressMatch) {
                let lastSaleFloorPrice = extractNumericalValue(
                  floorPriceDiffs["last sale"].floorPriceDiff
                );

                let find_description = `${
                  global_name ? global_name : record.contractAddress
                } ${tokenId} sold to ${records[0].transaction.to_address} by ${
                  records[1].transaction.to_address
                } in ${record.interactedMarket} at ${
                  records[0].transaction.floor_price_diff
                } of floor after ${timeDifferenceMinutes} minutes`;
                let findType: FindingType = FindingType.Info;
                let find_name = `indexed-nft-sale`;
                let floorDiffs =
                  Math.abs(
                    extractNumericalValue(
                      floorPriceDiffs["current sale"].floorPriceDiff
                    )
                  ) - Math.abs(lastSaleFloorPrice);
                let currentSaleFloorPrice = extractNumericalValue(
                  floorPriceDiffs["current sale"].floorPriceDiff
                );
                let alert: Finding;
                let alertLabel: Label[] = [];
                let regularSaleExtra = `, for a value of ${truncateDecimal(
                  records[0].transaction.avg_item_price
                )} ${chainCurrency} where the price floor is ${
                  records[0].transaction.floor_price
                } ${chainCurrency}`;

                if (floorDiffs < 0) floorDiffs *= -1;
                console.log(
                  "----- floorDiffs -----",
                  floorDiffs,
                  lastSaleFloorPrice
                );
                console.log(
                  "----- stolen sale condition -----",
                  floorDiffs > 85,
                  currentSaleFloorPrice > 0,
                  lastSaleFloorPrice <= -98
                );

                if (
                  (floorDiffs > 80 || currentSaleFloorPrice > 0) &&
                  lastSaleFloorPrice <= -98
                ) {
                  let victim = records[1].transaction.from_address;
                  let attacker = records[1].transaction.to_address;
                  let profit = Math.abs(avgItemPriceDifference).toFixed(3);
                  find_description = `${global_name} ${tokenId} sold to ${records[0].transaction.to_address} by ${records[1].transaction.to_address} possibly stolen from ${victim} in ${record.interactedMarket} at ${records[0].transaction.floor_price_diff} of floor after ${timeDifferenceMinutes} minutes for a profit of ${profit} ${chainCurrency}`;
                  findType = FindingType.Exploit;
                  find_name = `stolen-nft-sale`;

                  alertLabel.push({
                    entityType: EntityType.Address,
                    entity: `${tokenId},${record.contractAddress}`,
                    label: "stolen-nft",
                    confidence: 0.8,
                    remove: false,
                    metadata: {},
                  });

                  alertLabel.push({
                    entityType: EntityType.Address,
                    entity: `${victim}`,
                    label: "nft-phishing-victim",
                    confidence: 0.8,
                    remove: false,
                    metadata: {},
                  });

                  alertLabel.push({
                    entityType: EntityType.Address,
                    entity: `${attacker}`,
                    label: "nft-phishing-attacker",
                    confidence: 0.8,
                    remove: false,
                    metadata: {},
                  });

                  alertLabel.push({
                    entityType: EntityType.Transaction,
                    entity: `${records[1].transaction.transaction_hash}`,
                    label: "nft-phishing-attack-hash",
                    confidence: 0.8,
                    remove: false,
                    metadata: {},
                  });

                  alert = createCustomAlert(
                    record,
                    find_description + regularSaleExtra,
                    find_name,
                    findType,
                    FindingSeverity.High,
                    chainId,
                    floorPriceDiffs
                  );

                  alert.addresses.push(victim);
                  alert.addresses.push(attacker);
                } else {
                  alert = createCustomAlert(
                    record,
                    find_description + regularSaleExtra,
                    find_name,
                    findType,
                    FindingSeverity.Info,
                    chainId,
                    floorPriceDiffs
                  );
                  alertLabel.push({
                    entityType: EntityType.Address,
                    entity: `${tokenId},${record.contractAddress}`,
                    label: "indexed-nft-sale",
                    confidence: 0.9,
                    remove: false,
                    metadata: {},
                  });
                  alert.addresses.push(records[1].transaction.to_address);
                  alert.addresses.push(records[0].transaction.to_address);
                  alert.addresses.push(records[0].transaction.from_address);
                }
                alert.metadata.lastTxn =
                  records[1].transaction.transaction_hash;

                Object.keys(filteredAddresses).forEach((address: string) => {
                  alert.addresses.push(address);
                });

                for (const label of alertLabel) {
                  alert.labels.push(label);
                }

                findings.push(alert);
              }
            } else {
              console.log("----- Only one record available -----");
              /*
              ONLY ONE RECORD AVAILABLE:
              + record is the tx that was just indexed
              + create alerts based on current data (no comparison)
              + ALERTS:
              + sold for more than 120% floor price
                + sold for less than -99% floor price or -100%
                + regular sales
            */

              // get the floor price change ie: -99% or 350%
              const numericalValue = extractNumericalValue(
                record.floorPriceDiff
              );
              if (record.tokens) {
                for (const tokenKey in record.tokens) {
                  const token = record.tokens[tokenKey];
                  const tokenName =
                    token.name || shortenAddress(record.contractAddress);
                  let alert_description;
                  let alert_name;
                  let alert_type: FindingType = FindingType.Info;
                  let alert_severity = FindingSeverity.Info;

                  const currencyName =
                    token.price.currency.name === "ETH"
                      ? chainCurrency
                      : token.price.currency.name;
                  const floorMessage = record.floorPrice
                    ? `with collection floor of ${record.floorPrice.toFixed(
                        4
                      )} ${currency}`
                    : `(no floor price detected)`;
                  const extraInfo = `at ${record.avgItemPrice.toFixed(
                    5
                  )} ${currencyName} ${floorMessage}`;
                  const isZeroERC20 =
                    record.avgItemPrice == 0 && ercToNativeMSG ? true : false;

                  if (numericalValue >= 20) {
                    alert_name = `nft-sold-above-floor-price`;
                    alert_description = `${tokenName} ${tokenKey} sold for more than 110% of the floor price, ${extraInfo}`;
                    // labels on alerts.ts
                  } else if (
                    numericalValue >= -100 &&
                    numericalValue <= -98 &&
                    !isZeroERC20
                  ) {
                    alert_severity = FindingSeverity.Medium;
                    alert_type = FindingType.Suspicious;
                    alert_name =
                      floorPriceUSD < MIN_USD_VALUE
                        ? `nft-potential-low-value-phishing-sale`
                        : `nft-phishing-sale`;

                    alert_description = `${tokenName} ${tokenKey} sold for less than -99% of the floor price, ${extraInfo}`;
                    // labels on alerts.ts
                  } else {
                    /**
                     * ALL NEW REGULAR SALES GO HERE
                     */

                    let currencyType = chainCurrency;
                    if (find && tokenKey && find.tokens[tokenKey]) {
                      const market = Object.values(
                        find.tokens[tokenKey].markets!
                      )[0];
                      currencyType =
                        market.price.currency.name === "ETH"
                          ? chainCurrency
                          : market.price.currency.name;
                    }

                    alert_name = "nft-sale";
                    if (isZeroERC20)
                      alert_name = "nft-sale-erc20-price-unknown";
                    if (floorPriceUSD == 0)
                      alert_name = "nft-sale-floor-price-unknown";
                    const customValue = `${
                      nativeERC20value != 0
                        ? sumValues[extraERC20[0].name]
                        : truncateDecimal(record.avgItemPrice)
                    }`;
                    alert_description = `${tokenName} id ${tokenKey} sold at ${customValue} ${
                      currencyType || chainCurrency
                    } ${
                      ercToNativeMSG ? ercToNativeMSG : ""
                    } ${floorMessage} (${record.floorPriceDiff})`;
                    // labels on alerts.ts
                  }

                  const alert = createCustomAlert(
                    record,
                    alert_description,
                    alert_name,
                    alert_type,
                    alert_severity,
                    chainId,
                    { tokenKey: tokenKey }
                  );

                  Object.keys(filteredAddresses).forEach((address: string) => {
                    alert.addresses.push(address);
                  });
                  findings.push(alert);
                }
              } else {
                console.log("record.tokens is undefined or null", txEvent.hash);
              }
            }
          }
        }
      } catch (e) {
        console.log(
          `Agent Error: ${e} in tx ${txEvent.hash}, contract ${info.address}`
        );
      }
    }

    return findings;
  };

export default {
  initialize,
  handleTransaction: provideHandleTransaction(getOpenSeaFloorData),
};
