import {
  FindingType,
  FindingSeverity,
  Finding,
  HandleTransaction,
  Initialize,
  createTransactionEvent,
  ethers,
  Transaction,
} from "forta-agent";
import agent from "./agent";

interface BotSubscription {
  botId: string;
  alertId?: string;
  alertIds?: string[];
  chainId?: number;
}
interface AlertConfig {
  subscriptions: BotSubscription[];
}
interface InitializeResponse {
  alertConfig: AlertConfig;
}

import { utils } from "ethers";

import {
  createDriver,
  storeTransactionData,
  notifierCount,
  checkNotifier,
  deleteAllData,
  sharedReportsCount,
  setAddressTypeToNotifier,
  recipientExists,
  numberOfRecipients,
  senderExists,
} from "./db";
import {
  Driver,
  Result,
  auth,
  driver as createDriverInstance,
} from "neo4j-driver";
import { getSecrets } from "./storage";

jest.setTimeout(10000);

function getRandomTxHash() {
  const randomBytes = ethers.utils.randomBytes(32);
  const randomTxHash = ethers.utils.hexlify(randomBytes);
  return randomTxHash;
}

function getRandomAddress() {
  const bytes = utils.randomBytes(20);
  const randomAddress = utils.hexlify(utils.arrayify(bytes));
  return randomAddress;
}

function utf8ToHex(utf8String: string) {
  const utf8Bytes = ethers.utils.toUtf8Bytes(utf8String);
  const hexString = ethers.utils.hexlify(utf8Bytes);
  return hexString;
}

function createTx(from: string, to: string, data: string, customHash?: string) {
  const mockTransaction: Transaction = {
    hash: customHash || getRandomTxHash(),
    from: from,
    to: to,
    data: utf8ToHex(data),
    value: "0",
    gasPrice: "0",
    nonce: 0,
    gas: "0",
    r: "0",
    v: "0",
    s: "0",
  };

  const mockTxEvent = createTransactionEvent({
    transaction: mockTransaction,
  } as any);

  return mockTxEvent;
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("SCAM-NOTIFIER-BOT db logic", () => {
  type Initialize = (test?: boolean) => Promise<InitializeResponse | void>;
  let initialize: Initialize;
  let handleTransaction: HandleTransaction;
  let neo4jDriver: Driver;
  let N1: string;
  let N2: string;
  let G1: string;
  let S1: string;
  let S2: string;

  beforeEach(async () => {
    initialize = agent.initialize;
    handleTransaction = agent.handleTransaction;
    const keys = await getSecrets();
    neo4jDriver = createDriver(keys, "TEST");
    N1 = getRandomAddress();
    N2 = getRandomAddress();
    G1 = getRandomAddress();
    S1 = getRandomAddress();
    S2 = getRandomAddress();
    await initialize(true);
  });

  afterEach(async () => {
    await deleteAllData(neo4jDriver);
  });

  describe("Bot Alerts Test", () => {
    it("Creates an alert when a notifier sends a transaction to a scam address", async () => {
      // Set a notifier address
      await storeTransactionData(
        neo4jDriver,
        N1,
        S1,
        getRandomTxHash(),
        "EOA",
        "Alert ONE",
        true // N1 is now a notifier
      );

      const N1_IsNotifier = await checkNotifier(neo4jDriver, N1);
      expect(N1_IsNotifier).toBe(true);

      const newAlertTx = createTx(N1, S1, "this is a scam");

      const newAlert = await handleTransaction(newAlertTx);
      expect(newAlert).toStrictEqual([
        Finding.fromObject({
          name: "Scam Notifier Alert",
          description: `${S1} was flagged as a scam by ${N1} `,
          alertId: "SCAM-NOTIFIER-EOA",
          protocol: "ethereum",
          severity: 4,
          timestamp: newAlert[0].timestamp,
          type: 2,
          metadata: {
            scammer_eoa: S1,
            notifier_eoa: N1,
            notifier_name: "",
            message: "this is a scam",
          },
          addresses: [],
          labels: [
            {
              confidence: 0.8,
              entity: N1,
              entityType: 1,
              label: "notifier_EOA",
              metadata: {
                ENS_NAME: "",
              },
              remove: false,
            },
            {
              confidence: 0.8,
              entity: S1,
              entityType: 1,
              label: "scammer_EOA",
              metadata: {},
              remove: false,
            },
          ],
        }),
      ]);
    });

    it("Creates an VICTIM alert when a notifier sends a transaction to a scam address", async () => {
      // Set a notifier address
      await storeTransactionData(
        neo4jDriver,
        N1,
        S1,
        getRandomTxHash(),
        "EOA",
        "Alert ONE",
        true // N1 is now a notifier
      );

      const N1_IsNotifier = await checkNotifier(neo4jDriver, N1);
      expect(N1_IsNotifier).toBe(true);

      const newAlertTx = createTx(
        N1,
        S1,
        "Your token (MATIC) has been approved to the scammer (0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73). Please see the detailed report https://metasleuth.io/report?report_id=24850a6cf72a587a9a1ac0fe120845cf Revoke your approval to the scammer immediately to prevent further loss. Read this document on how to revoke your approval: https://docs.blocksec.com/metadock/features/approval-diagnosis"
      );

      const newAlert = await handleTransaction(newAlertTx);
      expect(newAlert).toStrictEqual([
        Finding.fromObject({
          name: "Scam Notifier Alert",
          description: `${N1} alerted ${S1} from a MATIC phishing approval to 0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73`,
          alertId: "VICTIM-NOTIFIER-EOA",
          protocol: "ethereum",
          timestamp: newAlert[0].timestamp,
          severity: 4,
          type: 1,
          metadata: {
            scammer_eoa: "0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73",
            notifier_eoa: N1,
            notifier_name: "",
            message:
              "Your token (MATIC) has been approved to the scammer (0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73). Please see the detailed report https://metasleuth.io/report?report_id=24850a6cf72a587a9a1ac0fe120845cf Revoke your approval to the scammer immediately to prevent further loss. Read this document on how to revoke your approval: https://docs.blocksec.com/metadock/features/approval-diagnosis",
            victim_eoa: S1,
          },
          addresses: [],
          labels: [
            {
              confidence: 0.8,
              entity: N1,
              entityType: 1,
              label: "notifier_EOA",
              metadata: {
                ENS_NAME: "",
              },
              remove: false,
            },
            {
              confidence: 0.8,
              entity: S1,
              entityType: 1,
              label: "victim_EOA",
              metadata: {},
              remove: false,
            },
            {
              confidence: 0.8,
              entity: "0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73",
              entityType: 1,
              label: "scammer_EOA",
              metadata: {},
              remove: false,
            },
          ],
        }),
      ]);
    });

    it("Adds a general address when it sends a transaction to a known scam address", async () => {
      // Let S1 be a known scam address
      await storeTransactionData(
        neo4jDriver,
        N1,
        S1,
        getRandomTxHash(),
        "EOA",
        "Alert ONE",
        true
      );

      const G1_IsNotifier = await checkNotifier(neo4jDriver, G1);
      expect(G1_IsNotifier).toBe(false);

      const newAlertTx = createTx(G1, S1, "scam honeypot", "custom_hash");

      const consoleSpy = jest.spyOn(console, "log");
      await handleTransaction(newAlertTx);
      expect(consoleSpy).toHaveBeenCalledWith(
        "[Success] [Regular] Saved transaction data custom_hash msg: scam honeypot"
      );
      consoleSpy.mockRestore();

      const G1_ExistInDb = await senderExists(neo4jDriver, G1);
      expect(G1_ExistInDb).toBe(true);

      const G1_IsNotifierAfterAddedToDb = await checkNotifier(neo4jDriver, G1);
      expect(G1_IsNotifierAfterAddedToDb).toBe(false);
    });

    it("Regular address becomes a new notifier when it flags at least 2 scam addresses", async () => {
      // Let S1 be a known scam address
      await storeTransactionData(
        neo4jDriver,
        N1,
        S1,
        getRandomTxHash(),
        "EOA",
        "Alert ONE",
        true
      );

      const prepAlertTx = createTx(G1, S1, "scam honeypot", "custom_hash");
      await handleTransaction(prepAlertTx);

      // Another notifier sends a transaction to a another scam address
      await storeTransactionData(
        neo4jDriver,
        N2,
        S2,
        getRandomTxHash(),
        "EOA",
        "Alert THIS IS ALSO A SCAM"
      );

      // General Address also sends a transaction to the same scam address
      // Now it would have 2 flagged scam addresses

      const newAlertTx = createTx(G1, S2, "scam honeypot TWO");

      const newAlert = await handleTransaction(newAlertTx);

      const G1_IsNotifier = await checkNotifier(neo4jDriver, G1);
      // changed to false as now it added manually
      expect(G1_IsNotifier).toBe(false);

      let recipientNums = await numberOfRecipients(neo4jDriver, G1);

      expect(newAlert).toStrictEqual([
        Finding.fromObject({
          name: "Scam Notifier Alert",
          description: `New scam notifier identified ${G1} `,
          alertId: "NEW-SCAM-NOTIFIER",
          protocol: "ethereum",
          timestamp: newAlert[0].timestamp,
          severity: 1,
          type: 4,
          metadata: {
            similar_notifier_eoa: recipientNums[0],
            similar_notifier_name: "Not Found",
            union_flagged: `${recipientNums[0]}, ${recipientNums[1]}`,
            notifierName: "Not found",
            message: "scam honeypot TWO",
          },
          addresses: [],
          labels: [
            {
              confidence: 1.0,
              entity: G1,
              entityType: 1,
              label: "new_notifier_EOA",
              metadata: {
                ENS_NAME: "",
              },
              remove: false,
            },
            {
              confidence: 0.8,
              entity: S2,
              entityType: 1,
              label: "scammer_EOA",
              metadata: {},
              remove: false,
            },
            {
              confidence: 0.8,
              entity: recipientNums[0],
              entityType: 1,
              label: "union_flagged",
              metadata: {},
              remove: false,
            },
            {
              confidence: 0.8,
              entity: recipientNums[1],
              entityType: 1,
              label: "union_flagged",
              metadata: {},
              remove: false,
            },
          ],
        }),
      ]);
    });
  });

  describe("Core DB Logic Test", () => {
    afterEach(async () => {
      // Wait for a short duration after each test to ensure all async operations have completed
      await sleep(4500);
    });

    it("Adds Notifiers/Regular transactions, checks for number of notifiers and status of senders ", async () => {
      const bob = getRandomAddress();
      const alice = getRandomAddress();
      const hash = getRandomTxHash();

      // stores a new transaction
      const storeResult = await storeTransactionData(
        neo4jDriver,
        bob,
        alice,
        hash,
        "EOA",
        "Honeypot creator",
        true
      );

      const storeResultDup = await storeTransactionData(
        neo4jDriver,
        bob,
        alice,
        hash,
        "EOA",
        "Honeypot creator",
        true
      );

      const nCount = await notifierCount(neo4jDriver);
      expect(nCount).toBe(1);
      expect(storeResult).toBe(true);
      expect(storeResultDup).toBe(false);

      const storeResultTwo = await storeTransactionData(
        neo4jDriver,
        getRandomAddress(),
        alice,
        getRandomTxHash(),
        "EOA",
        "Honeypot creator"
      );

      const nCountTwo = await notifierCount(neo4jDriver);
      expect(nCountTwo).toBe(2);
      const regularAddress = await checkNotifier(neo4jDriver, alice);
      expect(regularAddress).toBe(false);
    });

    it("Creates a new notifier if the address shares a subset of an already existing notifier", async () => {
      const toAddresses = Array.from({ length: 10 }, () => getRandomAddress());
      const messages = Array.from(
        { length: 10 },
        () => `Message ${Math.random()}`
      );

      const originalNotifier = getRandomAddress();
      const newNotifier = getRandomAddress();

      // Create 10 transactions from the same address, each to a different address
      for (let i = 0; i < 10; i++) {
        const hash = getRandomTxHash();
        await storeTransactionData(
          neo4jDriver,
          originalNotifier,
          toAddresses[i],
          hash,
          "EOA",
          messages[i]
        );
      }

      // Create 2 transactions from a new address to two of the first 10 'to' addresses
      const hash1 = getRandomTxHash();
      const hash2 = getRandomTxHash();
      const message1 = `Message ${Math.random()}`;
      const message2 = `Message ${Math.random()}`;

      await storeTransactionData(
        neo4jDriver,
        newNotifier,
        toAddresses[0],
        hash1,
        "EOA",
        message1
      );

      await storeTransactionData(
        neo4jDriver,
        newNotifier,
        toAddresses[1],
        hash2,
        "EOA",
        message2
      );

      const sharedReports = await numberOfRecipients(neo4jDriver, newNotifier);
      expect(sharedReports.length).toBe(1);
      await setAddressTypeToNotifier(neo4jDriver, newNotifier);
      const nowNotifier = await checkNotifier(neo4jDriver, newNotifier);
      expect(nowNotifier).toBe(true);
    });

    it("Tests shared recipient msg", async () => {
      await storeTransactionData(
        neo4jDriver,
        "one",
        "scam 1",
        "0xefe60d9c4226f7d5c358f7cc863f0230c03418b9b50c61b540095f4ae4567785",
        "EOA",
        "Rugcode line 887. ",
        true
      );

      let recipientAlreadyExists = await recipientExists(neo4jDriver, "scam 1");
      let recipientNums = await numberOfRecipients(neo4jDriver, "one");
      expect(recipientNums).toStrictEqual([]);
      expect(recipientAlreadyExists).toBe(true);
      await storeTransactionData(
        neo4jDriver,
        "two",
        "scam 1",
        "0xefe60d9c4226f7d5c358f7cc863f0230c03418b9b50c61b540095f4ae45676565",
        "EOA",
        "Rugcode line 887. "
      );

      recipientNums = await numberOfRecipients(neo4jDriver, "one");
      expect(recipientNums.length).toBe(1);
    });

    it("Code db interact", async () => {
      // scam-warning.eth
      await storeTransactionData(
        neo4jDriver,
        "0xcd5496ef9d7fb6657c9f1a4a1753f645994fbfa9",
        "0x1bc5b686c41ab965954f7aeca2dd01d74796ce0d",
        "0xefe60d9c4226f7d5c358f7cc863f0230c03418b9b50c61b540095f4ae4567785",
        "EOA",
        "Alert",
        true
      );

      // 🛑scam-warning🛑.eth
      await storeTransactionData(
        neo4jDriver,
        "0xba6e11347856c79797af6b2eac93a8145746b4f9",
        "0x207a7f9977ab793637028b5cf6389da9e28f15d5",
        "0x83e0e3876745c31d27f1f0a8542fbc3eb704c286e40172ee4296505a14058042",
        "EOA",
        `Alert`,
        true
      );

      // 🔴dev-will-dump-on-you🔴.eth
      await storeTransactionData(
        neo4jDriver,
        "0xc574962311141cb505c09fd973c4630b8f7c4a81",
        "0x2018ac66555591cb0c278ae0919215721eb3bf48",
        "0xfba60ae0a2b08a5ef8fcbac5c2c06a79c437e9d878d425a6b617d1931c369110",
        "EOA",
        "Alert",
        true
      );

      // metasleuth911.eth
      await storeTransactionData(
        neo4jDriver,
        "0x666a3ce3f9438dccd4a885ba5b565f3035984793",
        "0x87e4158f3410f10cee9329ba2d8b79865d9780de",
        "0x2963aca299858d01b1370ec85c95450e772fdeb9526e6a2417569c4070422405",
        "EOA",
        "Alert",
        true
      );
    });
  });

  afterAll(() => {
    neo4jDriver.close();
  });
});
