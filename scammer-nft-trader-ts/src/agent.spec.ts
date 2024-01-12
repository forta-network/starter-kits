import {
  FindingType,
  FindingSeverity,
  Finding,
  createTransactionEvent,
  TransactionEvent,
  ethers,
} from "forta-agent";

import db from "./db";
import agent, { initialize, provideHandleTransaction } from "./agent";

import {
  getRandomAddress,
  getRandomTxHash,
  createBatchContractInfo,
  wait,
} from "./utils/tests";
import {
  addTransactionRecord,
  getTransactionByHash,
  getLatestTransactionRecords,
} from "./client";
import type { MarketName, TransactionRecord } from "./types/types";
import type { NftContract } from "alchemy-sdk";

function newRecord(
  fromAddr: string,
  toAddr: string,
  initiator: string,
  contractAddress: string,
  hash: string
) {
  const record: TransactionRecord = {
    interactedMarket: "opensea" as MarketName,
    transactionHash: hash,
    toAddr: toAddr,
    fromAddr: fromAddr,
    initiator: initiator,
    totalPrice: 1,
    totalPriceInUSD: 1,
    avgItemPrice: 1,
    contractAddress: contractAddress,
    floorPrice: 1,
    currency: "ETH",
    timestamp: 1234567,
    tokens: {},
    floorPriceDiff: "0",
  };

  return record;
}

type HandleTransaction = (
  txEvent: TransactionEvent,
  test?: NftContract[]
) => Promise<Finding[]>;

jest.setTimeout(50000);
describe("NFT trader test", () => {
  let handleTransaction: HandleTransaction;
  let getOpenSeaFloorData = jest.fn();
  const mockTxEvent = createTransactionEvent({} as any);

  let bob: string;
  let alice: string;
  let jack: string;
  let ca: string;

  beforeAll(async () => {
    handleTransaction = provideHandleTransaction(getOpenSeaFloorData);
    bob = getRandomAddress();
    alice = getRandomAddress();
    jack = getRandomAddress();
    ca = getRandomAddress();
    await initialize();
  });

  describe("Transaction records", () => {
    it("adds a new record", async () => {
      const txOneHash = getRandomTxHash();
      const record1 = newRecord(bob, alice, bob, ca, txOneHash);
      await addTransactionRecord(db, record1);
      const recordFromHash = await getTransactionByHash(db, txOneHash);

      expect(recordFromHash).toEqual(record1);
    });

    it("adds multiple records", async () => {
      const txOneHash = getRandomTxHash();
      const record1 = newRecord(bob, alice, bob, ca, txOneHash);
      await addTransactionRecord(db, record1);

      const txTwoHash = getRandomTxHash();
      const record2 = newRecord(bob, alice, bob, ca, txTwoHash);
      await addTransactionRecord(db, record2);

      const recordFromHash1 = await getTransactionByHash(db, txOneHash);
      const recordFromHash2 = await getTransactionByHash(db, txTwoHash);

      expect(recordFromHash1).toEqual(record1);
      expect(recordFromHash2).toEqual(record2);
    });

    it("throws an error when adding a record with duplicate hash", async () => {
      expect.assertions(1);
      const ca2 = getRandomAddress();
      const txOneHash = getRandomTxHash();
      const record1 = newRecord(bob, alice, bob, ca, txOneHash);
      await addTransactionRecord(db, record1);

      const record2 = newRecord(alice, bob, alice, ca2, txOneHash);

      await expect(addTransactionRecord(db, record2)).rejects.toThrow(
        "SQLITE_CONSTRAINT: UNIQUE constraint failed: transactions.transaction_hash"
      );
    });
  });

  describe("Records and retrives tx from db", () => {
    it("Stores New Tx on the db and triggers info alert", async () => {
      let randomContract = getRandomAddress();
      let txHash = getRandomTxHash();
      let [mockApi, demoEvent] = createBatchContractInfo(
        randomContract,
        "TEST NFT CONTRACT",
        "TSTNFT",
        "100",
        "ERC721",
        [95],
        100,
        bob,
        alice,
        ["777"],
        txHash
      );

      getOpenSeaFloorData.mockResolvedValueOnce({
        floorPrice: 100,
        currency: "ETH",
        numberOfOwners: 3432423,
        totalSales: 342342,
        totalVolume: 23,
      });

      const findings = await handleTransaction(demoEvent, mockApi);

      expect(findings.length).toBe(1);
      expect(findings[0].metadata.floorPriceDiff).toBe("-5.00%");
      expect(findings[0].metadata.fromAddr).toBe(bob);
      expect(findings[0].metadata.toAddr).toBe(alice);
      expect(findings[0].labels).toStrictEqual([
        {
          entityType: 1,
          entity: `777,${randomContract}`,
          label: "nft-sale-record",
          confidence: 0.9,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: bob,
          label: "nft-sender",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: alice,
          label: "nft-receiver",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
      ]);
    });
  });

  describe("Only one indexed record txns", () => {
    it("Sale at <99% floorPrice [possible phishing]", async () => {
      // Creates a first sale, 1 value when floor is 100
      let randomContract = getRandomAddress();
      let txHash = getRandomTxHash();
      let [mockApi, demoEvent] = createBatchContractInfo(
        randomContract,
        "TEST NFT CONTRACT",
        "TSTNFT",
        "100",
        "ERC721",
        [1],
        100,
        bob,
        jack,
        ["1"],
        txHash
      );

      getOpenSeaFloorData.mockResolvedValueOnce({
        floorPrice: 100,
        currency: "ETH",
        numberOfOwners: 3432423,
        totalSales: 342342,
        totalVolume: 23,
      });
      const findings = await handleTransaction(demoEvent, mockApi);

      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe(3);
      expect(findings[0].metadata.floorPriceDiff).toBe("-99.00%");
      expect(findings[0].labels).toStrictEqual([
        {
          entityType: 1,
          entity: `1,${randomContract}`,
          label: "nft-phising-transfer",
          confidence: 0.9,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: `${findings[0].metadata.fromAddr}`,
          label: "nft-phishing-victim",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: `${findings[0].metadata.toAddr}`,
          label: "nft-phishing-attacker",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
      ]);
    });

    it("Sale at >120% floorPrice", async () => {
      // Creates a first sale, 120 value when floor is 100
      let randomContract = getRandomAddress();
      let txHash = getRandomTxHash();
      let [mockApi, demoEvent] = createBatchContractInfo(
        randomContract,
        "TEST NFT CONTRACT",
        "TSTNFT",
        "100",
        "ERC721",
        [120],
        100,
        bob,
        alice,
        ["1"],
        txHash
      );
      getOpenSeaFloorData.mockResolvedValueOnce({
        floorPrice: 100,
        currency: "ETH",
        numberOfOwners: 3432423,
        totalSales: 342342,
        totalVolume: 23,
      });
      const findings = await handleTransaction(demoEvent, mockApi);

      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe(1);
      expect(findings[0].metadata.floorPriceDiff).toBe("+20.00%");
      expect(findings[0].labels).toStrictEqual([
        {
          entityType: 1,
          entity: `1,${randomContract}`,
          label: "nft-sold-above-floor-price",
          confidence: 0.9,
          remove: false,
          metadata: {},
        },
      ]);
    });
  });

  describe("Multiple indexed record txns", () => {
    it("Regular two transfers", async () => {
      // Creates a first sale, id 1 for 95 when floor is 100
      let randomContract = getRandomAddress();
      let txHash = getRandomTxHash();
      let [mockApi, demoEvent] = createBatchContractInfo(
        randomContract,
        "TEST NFT CONTRACT",
        "TSTNFT",
        "100",
        "ERC721",
        [95],
        100,
        bob, // from
        alice, // to
        ["1"],
        txHash
      );
      getOpenSeaFloorData.mockResolvedValueOnce({
        floorPrice: 100,
        currency: "ETH",
        numberOfOwners: 3432423,
        totalSales: 342342,
        totalVolume: 23,
      });
      const findings = await handleTransaction(demoEvent, mockApi);

      expect(findings[0].labels).toStrictEqual([
        {
          entityType: 1,
          entity: `1,${randomContract}`,
          label: "nft-sale-record",
          confidence: 0.9,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: bob,
          label: "nft-sender",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: alice,
          label: "nft-receiver",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
      ]);
      await wait(1);

      // Recipient sells the nft, at 105 with floor of 100
      let saleTxHash = getRandomTxHash();
      let [sellMockApi, sellDemoEvent] = createBatchContractInfo(
        randomContract,
        "TEST NFT CONTRACT",
        "TSTNFT",
        "100",
        "ERC721",
        [105],
        100,
        alice, // from
        jack,
        ["1"],
        saleTxHash
      );
      getOpenSeaFloorData.mockResolvedValueOnce({
        floorPrice: 100,
        currency: "ETH",
        numberOfOwners: 3432423,
        totalSales: 342342,
        totalVolume: 23,
      });
      const saleFindings = await handleTransaction(sellDemoEvent, sellMockApi);

      expect(saleFindings[0].labels).toStrictEqual([
        {
          entityType: 1,
          entity: `1,${randomContract}`,
          label: "indexed-nft-sale",
          confidence: 0.9,
          remove: false,
          metadata: {},
        },
      ]);
    });

    it("Phishing transfers", async () => {
      // Creates a first sale, id 1 for 1 when floor is 100
      let randomContract = getRandomAddress();
      let txHash = getRandomTxHash();
      let [mockApi, demoEvent] = createBatchContractInfo(
        randomContract,
        "TEST NFT CONTRACT",
        "TSTNFT",
        "10000",
        "ERC721",
        [1],
        100,
        bob, // from
        jack, // to
        ["1234"],
        txHash
      );
      getOpenSeaFloorData.mockResolvedValueOnce({
        floorPrice: 100,
        currency: "ETH",
        numberOfOwners: 3432423,
        totalSales: 342342,
        totalVolume: 23,
      });
      const findings = await handleTransaction(demoEvent, mockApi);

      expect(findings[0].severity).toBe(3);
      expect(findings[0].labels).toStrictEqual([
        {
          entityType: 1,
          entity: `1234,${randomContract}`,
          label: "nft-phising-transfer",
          confidence: 0.9,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: `${findings[0].metadata.fromAddr}`,
          label: "nft-phishing-victim",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: `${findings[0].metadata.toAddr}`,
          label: "nft-phishing-attacker",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
      ]);

      await wait(1);

      // Recipient sells the nft, at 95 with floor of 100
      let saleTxHash = getRandomTxHash();
      let [sellMockApi, sellDemoEvent] = createBatchContractInfo(
        randomContract,
        "TEST NFT CONTRACT",
        "TSTNFT",
        "10000",
        "ERC721",
        [95],
        100,
        jack, // from
        alice, // to
        ["1234"],
        saleTxHash
      );
      getOpenSeaFloorData.mockResolvedValueOnce({
        floorPrice: 100,
        currency: "ETH",
        numberOfOwners: 3432423,
        totalSales: 342342,
        totalVolume: 23,
      });
      const saleFindings = await handleTransaction(sellDemoEvent, sellMockApi);

      expect(saleFindings[0].severity).toBe(4);
      expect(saleFindings[0].labels).toStrictEqual([
        {
          entityType: 1,
          entity: `1234,${randomContract}`,
          label: "stolen-nft",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: `${bob}`,
          label: "nft-phishing-victim",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
        {
          entityType: 1,
          entity: `${jack}`,
          label: "nft-phishing-attacker",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
        {
          entityType: 2,
          entity: `${txHash}`,
          label: "nft-phishing-attack-hash",
          confidence: 0.8,
          remove: false,
          metadata: {},
        },
      ]);
    });
  });
});
