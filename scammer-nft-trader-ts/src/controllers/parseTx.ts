import _ from "lodash";

// modules
import { Network, TransactionEvent } from "forta-agent";
import { ethers } from "ethers";

// config
import { markets, currencies } from "../config/markets";
import { initializeTransactionData } from "../config/initialize";
import ABI from "../abi/ABI.json";

// parsers
import { parseSeaport } from "./parseSeaport";
import { parseLooksRare } from "./parseLooksRare";
import { parseBlur } from "./parseBlur";

// api
import { NftContract } from "alchemy-sdk";
import { getErc20TokenPrice } from "src/client";

async function transferIndexer(
  txEvent: TransactionEvent,
  contractData: NftContract
) {
  console.log("transferIndexer Running...");
  const contractAddress: string = contractData.address!;
  const transactionHash: string = txEvent.transaction.hash;
  const network: Network = txEvent.network;

  let recipient: string = txEvent.to ? txEvent.to : "";

  if (!(recipient.toLowerCase() in markets)) {
    console.log(`\n No market found for recipient ${recipient}\n`);
    return;
  }
  const tx = initializeTransactionData(
    transactionHash,
    contractData,
    recipient,
    contractAddress
  );

  const iface = new ethers.Interface(ABI);

  for (const log of txEvent.logs) {
    const logAddress = log.address.toLowerCase();
    if (logAddress in currencies) {
      tx.currency = currencies[logAddress as keyof typeof currencies];
    }
    const market = markets[logAddress];
    if (market && market.topics.includes(log.topics[0])) {
      switch (market.name) {
        case "opensea":
          console.log("parseSeaport...");
          await parseSeaport(tx, log, market, iface, network);
          break;
        case "looksrare":
          console.log("parseLooksRare...");
          parseLooksRare(tx, log, market, iface, network);
          break;
        case "blur":
          console.log("blur...");
          parseBlur(tx, log, market, iface, contractData, network);
          break;
        default:
      }
    }
  }
  return tx;
}

export { transferIndexer };
