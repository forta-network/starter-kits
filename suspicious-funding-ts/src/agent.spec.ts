import { HandleTransaction, Initialize, HandleBlock } from "forta-agent";
import {
  TestTransactionEvent,
  TestBlockEvent,
  MockEthersProvider,
} from "forta-agent-tools/lib/test";
import { createAddress } from "forta-agent-tools";
import { when } from "jest-when";

import { provideHandleTransaction, provideInitialize, provideHandleBlock } from "./agent";
import { createFinding } from "./utils";

class MockEthersProviderExtended extends MockEthersProvider {
  public getTransactionCount: any;
  public getCode: any;

  constructor() {
    super();
    this.getTransactionCount = jest.fn();
    this.getCode = jest.fn();
  }

  public setNonce(addr: string, nonce: number): MockEthersProviderExtended {
    when(this.getTransactionCount).calledWith(addr).mockReturnValue(nonce);
    return this;
  }

  public setCode(address: string, code: string): MockEthersProviderExtended {
    when(this.getCode)
      .calledWith(address)
      .mockReturnValue(Promise.resolve(code));
    return this;
  }
}

describe("Suspicious funding detector bot", () => {
  let handleTransaction: HandleTransaction;
  let handleBlock: HandleBlock;
  let initialize: Initialize;

  const mockProvider = new MockEthersProviderExtended();
  const mockTruePositiveFetcher = {
    getTruePositiveList: jest.fn()
  };
  const mockAttacker1 = createAddress("0x0123");
  const mockAttackers = new Map<string, { origin: string; hops: number }>([
    [mockAttacker1, { origin: "Tornado Cash", hops: 0 }],
  ]);

  beforeAll(async () => {
    mockProvider.setNetwork(1);
    initialize = provideInitialize(mockProvider as any, mockTruePositiveFetcher as any);
    handleTransaction = provideHandleTransaction(
      mockAttackers,
      mockProvider as any
    );
    handleBlock = provideHandleBlock(mockTruePositiveFetcher as any);

    await initialize();
  });

  describe("handleTransaction", () => {
    it("returns empty findings if there is no native token transfer", async () => {
      const mockTxEvent = new TestTransactionEvent()
        .setTo(createAddress("0xabc"))
        .setValue("0x0");
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns empty findings if there is a native token transfer but not from a past attacker", async () => {
      const mockTxEvent = new TestTransactionEvent()
        .setFrom(createAddress("0xdef"))
        .setTo(createAddress("0xabc"))
        .setValue("0x0");
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns empty findings if there is a native token transfer from an attacker but the value is over the threshold", async () => {
      const mockTxEvent = new TestTransactionEvent()
        .setFrom(mockAttacker1)
        .setTo(createAddress("0xabc"))
        .setValue("0xDE0B6B3A7640000"); // 1 ETH
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns empty findings if there is a native token transfer from an attacker to an old EOA", async () => {
      const mockTxTo = createAddress("0xabc");
      const mockTxEvent = new TestTransactionEvent()
        .setFrom(mockAttacker1)
        .setTo(mockTxTo)
        .setValue("0x01");

      mockProvider.setNonce(mockTxTo, 10000); // old EOA

      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns empty findings if there is a native token transfer from an attacker to a contract", async () => {
      const mockTxTo = createAddress("0xabc");
      const mockTxEvent = new TestTransactionEvent()
        .setFrom(mockAttacker1)
        .setTo(mockTxTo)
        .setValue("0x01");

      mockProvider.setNonce(mockTxTo, 0);
      mockProvider.setCode(mockTxTo, "0x1234"); // contract
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([]);
    });

    it("returns a finding if there is a native token transfer from an attacker to new EOA", async () => {
      const mockTxTo = createAddress("0xabc");
      const mockTxEvent = new TestTransactionEvent()
        .setFrom(mockAttacker1)
        .setTo(mockTxTo)
        .setValue("0x01");

      mockProvider.setNonce(mockTxTo, 0);
      mockProvider.setCode(mockTxTo, "0x");
      const findings = await handleTransaction(mockTxEvent);

      expect(findings).toStrictEqual([
        createFinding(mockAttacker1, mockTxTo, "Tornado Cash", 1),
      ]);
    });
  });

  describe("handleBlock", () => {
    it("doesn't attempt to fetch True Positive list if it is not the correct block number", async () => {
      const mockBlockNumber = 55;
      const mockBlockEvent = new TestBlockEvent().setNumber(mockBlockNumber);

      await handleBlock(mockBlockEvent);

      // Expect only one call, during the `initialize`
      expect(mockTruePositiveFetcher.getTruePositiveList).toHaveBeenCalledTimes(1)
    });

    it("attempts to fetcher True Positive list if it is the correct block number", async () => {
      const oneDay = 60 * 60 * 24;
      // Using Ethereum since the network was set to chainId of `1`
      const ethBlockTime = 12;
      const ethBlocksInOneDay = oneDay / ethBlockTime;

      const mockBlockEvent = new TestBlockEvent().setNumber(ethBlocksInOneDay);

      await handleBlock(mockBlockEvent);

      // Expect above call and during the `initialize`
      expect(mockTruePositiveFetcher.getTruePositiveList).toHaveBeenCalledTimes(2)
    });
  });
});
