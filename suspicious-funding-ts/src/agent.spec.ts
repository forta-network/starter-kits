import { HandleTransaction } from "forta-bot";
import {
  TestTransactionEvent,
  MockEthersProvider,
} from "forta-agent-tools/lib/test";
import { createAddress } from "forta-agent-tools";
import { when } from "jest-when";

import { provideHandleTransaction } from "./agent";
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

  const mockProvider = new MockEthersProviderExtended();
  const mockAttacker1 = createAddress("0x0123");
  const mockAttackers = new Map<string, { origin: string; hops: number }>([
    [mockAttacker1, { origin: "Tornado Cash", hops: 0 }],
  ]);

  beforeAll(async () => {
    mockProvider.setNetwork(1);
    handleTransaction = provideHandleTransaction(
      mockAttackers,
      mockProvider as any
    );
  });

  it("returns empty findings if there is no native token transfer", async () => {
    const mockTxEvent = new TestTransactionEvent()
      .setTo(createAddress("0xabc"))
      .setValue("0x0") as any;
    mockTxEvent.chainId = 1;
    const findings = await handleTransaction(mockTxEvent, mockProvider as any);

    expect(findings).toStrictEqual([]);
  });

  it("returns empty findings if there is a native token transfer but not from a past attacker", async () => {
    const mockTxEvent = new TestTransactionEvent()
      .setFrom(createAddress("0xdef"))
      .setTo(createAddress("0xabc"))
      .setValue("0x0") as any;
    mockTxEvent.chainId = 1;

    const findings = await handleTransaction(mockTxEvent, mockProvider as any);

    expect(findings).toStrictEqual([]);
  });

  it("returns empty findings if there is a native token transfer from an attacker but the value is over the threshold", async () => {
    const mockTxEvent = new TestTransactionEvent()
      .setFrom(mockAttacker1)
      .setTo(createAddress("0xabc"))
      .setValue("0xDE0B6B3A7640000") as any; // 1 ETH
    mockTxEvent.chainId = 1;

    const findings = await handleTransaction(mockTxEvent, mockProvider as any);

    expect(findings).toStrictEqual([]);
  });

  it("returns empty findings if there is a native token transfer from an attacker to an old EOA", async () => {
    const mockTxTo = createAddress("0xabc");
    const mockTxEvent = new TestTransactionEvent()
      .setFrom(mockAttacker1)
      .setTo(mockTxTo)
      .setValue("0x01") as any;
    mockTxEvent.chainId = 1;

    mockProvider.setNonce(mockTxTo, 10000); // old EOA

    const findings = await handleTransaction(mockTxEvent, mockProvider as any);

    expect(findings).toStrictEqual([]);
  });

  it("returns empty findings if there is a native token transfer from an attacker to a contract", async () => {
    const mockTxTo = createAddress("0xabc");
    const mockTxEvent = new TestTransactionEvent()
      .setFrom(mockAttacker1)
      .setTo(mockTxTo)
      .setValue("0x01") as any;
    mockTxEvent.chainId = 1;

    mockProvider.setNonce(mockTxTo, 0);
    mockProvider.setCode(mockTxTo, "0x1234"); // contract
    const findings = await handleTransaction(mockTxEvent, mockProvider as any);

    expect(findings).toStrictEqual([]);
  });

  it("returns a finding if there is a native token transfer from an attacker to new EOA", async () => {
    const mockTxTo = createAddress("0xabc");
    const mockTxEvent = new TestTransactionEvent()
      .setFrom(mockAttacker1)
      .setTo(mockTxTo)
      .setValue("0x01") as any;
    mockTxEvent.chainId = 1;

    mockProvider.setNonce(mockTxTo, 0);
    mockProvider.setCode(mockTxTo, "0x");
    const findings = await handleTransaction(mockTxEvent, mockProvider as any);

    expect(findings).toStrictEqual([
      createFinding(mockAttacker1, mockTxTo, "Tornado Cash", 1),
    ]);
  });
});
