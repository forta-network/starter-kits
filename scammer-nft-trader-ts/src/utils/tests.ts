import crypto from "crypto";
import { createTransactionEvent, TransactionEvent } from "forta-agent";

import { ethers } from "forta-agent";
import ABI from "../abi/ABI.json";

const iface = new ethers.utils.Interface(ABI);

export function wait(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

function encodeOrderFulfilledData({
  orderHash,
  offerer,
  zone,
  recipient,
  offer,
  consideration,
}: any) {
  const fragment = iface.getEvent("OrderFulfilled");
  if (!fragment) {
    throw new Error('Event "OrderFulfilled" not found in ABI');
  }
  const data = iface.encodeEventLog(fragment, [
    orderHash,
    offerer,
    zone,
    recipient,
    offer,
    consideration,
  ]);
  return data;
}

function toHexString(byteArray: Uint8Array): string {
  return (
    "0x" +
    Array.from(byteArray, (byte) => byte.toString(16).padStart(2, "0")).join("")
  );
}

export function getRandomTxHash(): string {
  const randomBytes = crypto.randomBytes(32);
  const randomTxHash = toHexString(new Uint8Array(randomBytes));
  return randomTxHash;
}

export function getRandomAddress(): string {
  const bytes = crypto.randomBytes(20);
  const randomAddress = toHexString(new Uint8Array(bytes)).toLowerCase();
  return randomAddress;
}

export function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

import Web3EthAbi from "web3-eth-abi";
import {
  NftTokenType,
  OpenSeaCollectionMetadata,
  NftContract,
} from "alchemy-sdk";
import { get } from "lodash";

export const createBatchContractInfo = (
  address: string,
  name: string,
  symbol: string,
  totalSupply: string,
  tokenType: string,
  price: number[],
  floorPrice: number,
  from: string,
  to: string,
  tokenId: string | string[],
  hash: string
): [NftContract[], TransactionEvent] => {
  let mockApiDataArray: NftContract[] = [];
  let nftContract: string = address;
  const mockOpenSeaCollectionMetadata: OpenSeaCollectionMetadata = {
    floorPrice: floorPrice,
  };

  const mockApiData: NftContract = {
    name: name,
    symbol: symbol,
    totalSupply: totalSupply,
    tokenType:
      tokenType == "ERC721" ? NftTokenType.ERC721 : NftTokenType.ERC1155,
    contractDeployer: getRandomAddress(),
    deployedBlockNumber: 999,
    openSea: mockOpenSeaCollectionMetadata,
    address: nftContract,
  };
  let offer = [];
  let consideration = [];

  for (let i = 0; i < tokenId.length; i++) {
    offer.push({
      itemType: 2,
      token: nftContract,
      identifier: tokenId[i],
      amount: 1,
    });
    consideration.push({
      itemType: 2,
      token: nftContract,
      identifier: tokenId[i],
      amount: 1,
      recipient: to,
    });
    consideration.push({
      itemType: 0,
      token: "0x0000000000000000000000000000000000000000",
      identifier: "0",
      amount: ethers.utils.parseEther(price[i].toString()),
      recipient: to,
    });
  }

  const SeaPortOrderData: any = encodeOrderFulfilledData({
    orderHash: crypto.randomBytes(32),
    offerer: from,
    zone: getRandomAddress(),
    recipient: to,
    offer,
    consideration,
  });

  const currentTimestamp = getCurrentTimestamp();
  const mockEvent = createTransactionEvent({
    timestamp: currentTimestamp,
    transaction: {
      hash: hash,
      from: getRandomAddress(),
      to: "0x00000000006c3852cbef3e08e8df289169ede581",
    },
    addresses: {
      "0x00000000006c3852cbef3e08e8df289169ede581": true,
    },
    logs: [
      {
        address: "0x00000000006c3852cbef3e08e8df289169ede581",
        topics: [
          "0x9d9af8e38d66c62e2c12f0225249fd9d721c54b83f48d9352c97c6cacdcb6f31",
          Web3EthAbi.encodeParameter("address", from),
          Web3EthAbi.encodeParameter("address", to),
        ],
        data: SeaPortOrderData.data,
        logIndex: 1,
        blockNumber: 16217012,
        blockHash:
          "0x4b1f94a7fc5ca5bb74bde07406c1187b0d4dc12c4aacb11972cf2e7fe5fc9608",
        transactionIndex: 1,
        transactionHash: hash,
        removed: false,
      },
    ],
  } as any);

  if (tokenId instanceof Array) {
    for (let i = 0; i < tokenId.length; i++) {
      let newTransferLog = {
        address: address,
        topics: [
          "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
          Web3EthAbi.encodeParameter("address", from),
          Web3EthAbi.encodeParameter("address", to),
          Web3EthAbi.encodeParameter("uint256", tokenId[i]),
        ],
        data: "0x",
        logIndex: i + 1,
        blockNumber: 16217012,
        blockHash:
          "0x4b1f94a7fc5ca5bb74bde07406c1187b0d4dc12c4aacb11972cf2e7fe5fc9608",
        transactionIndex: 1 + 1,
        transactionHash: hash,
        removed: false,
      };

      mockEvent.logs.push(newTransferLog);
    }
  } else {
    mockEvent.logs.push({
      address: address,
      topics: [
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        Web3EthAbi.encodeParameter("address", from),
        Web3EthAbi.encodeParameter("address", to),
        Web3EthAbi.encodeParameter("uint256", tokenId),
      ],
      data: "0x",
      logIndex: 2,
      blockNumber: 16217012,
      blockHash:
        "0x4b1f94a7fc5ca5bb74bde07406c1187b0d4dc12c4aacb11972cf2e7fe5fc9608",
      transactionIndex: 2,
      transactionHash: hash,
      removed: false,
    });
  }

  mockApiDataArray.push(mockApiData);

  return [mockApiDataArray, mockEvent];
};
