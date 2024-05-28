import {
  FindingType,
  FindingSeverity,
  Finding,
  HandleTransaction,
  ethers,
  Label,
  EntityType,
} from "forta-agent";
import { provideHandleTransaction, ERC20_TRANSFER_EVENT } from "./agent";
import { when } from "jest-when";
import { Interface } from "ethers/lib/utils";
import { createAddress } from "forta-agent-tools";
import {
  MockEthersProvider,
  TestTransactionEvent,
} from "forta-agent-tools/lib/test";

jest.mock("node-fetch");

// Mock the fetchJwt function of the forta-agent module
const mockFetchJwt = jest.fn();
jest.mock("forta-agent", () => {
  const original = jest.requireActual("forta-agent");
  return {
    ...original,
    fetchJwt: () => mockFetchJwt(),
  };
});

class MockEthersProviderExtended extends MockEthersProvider {
  public getTransactionCount: any;
  public getCode: any;

  constructor() {
    super();
    this.getTransactionCount = jest.fn();
    this.getCode = jest.fn();
  }

  public setNonce(
    addr: string,
    block: number,
    nonce: number
  ): MockEthersProviderExtended {
    when(this.getTransactionCount)
      .calledWith(addr, block)
      .mockReturnValue(nonce);
    return this;
  }

  public setCode(
    address: string,
    code: string,
    blockNumber: number
  ): MockEthersProviderExtended {
    when(this.getCode)
      .calledWith(address, blockNumber)
      .mockReturnValue(Promise.resolve(code));
    return this;
  }
}

export const testCreateFinding = (
  token: string,
  usdValue: string,
  txHash: string,
  mintRecipient: string,
  severity: FindingSeverity,
  txFrom: string
): Finding => {
  let labels: Label[] = [];
  let metadata: {
    [key: string]: string;
  } = {};
  metadata["initiator"] = txFrom;
  metadata["token"] = token;
  metadata["usdValue"] = usdValue;
  metadata["txHash"] = txHash;
  metadata["mintRecipient"] = mintRecipient;

  labels.push(
    Label.fromObject({
      entity: mintRecipient,
      entityType: EntityType.Address,
      label: "Attacker",
      confidence:
        severity === FindingSeverity.High
          ? 0.7
          : severity === FindingSeverity.Medium
          ? 0.6
          : 0.5,
      remove: false,
    })
  );

  labels.push(
    Label.fromObject({
      entity: txHash,
      entityType: EntityType.Transaction,
      label: "Attack",
      confidence:
        severity === FindingSeverity.High
          ? 0.7
          : severity === FindingSeverity.Medium
          ? 0.6
          : 0.5,
      remove: false,
    })
  );

  return Finding.fromObject({
    name: "Suspicious Mint",
    description:
      severity === FindingSeverity.High
        ? `Token mint of >$50k to ${mintRecipient} detected`
        : severity === FindingSeverity.Medium
        ? `Token mint of >$10k to new EOA ${mintRecipient} detected`
        : `Token mint of unknown value to new EOA ${mintRecipient} detected`,
    alertId:
      severity === FindingSeverity.High
        ? "SUSPICIOUS-MINT-1"
        : severity === FindingSeverity.Medium
        ? "SUSPICIOUS-MINT-2"
        : "SUSPICIOUS-MINT-3",
    severity,
    type: FindingType.Suspicious,
    metadata,
    labels,
  });
};

const mockTxFrom = createAddress("0x1234");
const TEST_TOKEN = createAddress("0x2222");
const TRANSFER_IFACE = new Interface([ERC20_TRANSFER_EVENT]);

const transferEvent = TRANSFER_IFACE.getEvent("Transfer");

// used to avoid short logs filtering
const randomEvent = new Interface(["event RandomEvent()"]).getEvent(
  "RandomEvent"
);

describe("Suspicious Mint Bot test suite", () => {
  const mockProvider: MockEthersProviderExtended =
    new MockEthersProviderExtended();
  const mockFetcher = {
    getValueInUsd: jest.fn(),
  };

  const handleTransaction: HandleTransaction = provideHandleTransaction(
    mockProvider as any,
    mockFetcher as any
  );

  beforeEach(() => {
    mockProvider.setNetwork(1);
  });

  it("should return empty findings if there is no token mint", async () => {
    const data = [
      createAddress("0x222"), // Not a mint
      mockTxFrom,
      ethers.BigNumber.from("3424324324423423"),
    ];

    const txEvent = new TestTransactionEvent()
      .setFrom(mockTxFrom)
      .setBlock(10)
      .setHash("0x1")
      .addEventLog(transferEvent, TEST_TOKEN, data);

    const findings = await handleTransaction(txEvent);
    expect(findings).toStrictEqual([]);
  });

  it("should return a High severity finding if the usd value of the minted token is over $50000", async () => {
    const data = [
      createAddress("0x0"),
      mockTxFrom,
      ethers.BigNumber.from("3424324324423423"),
    ];

    const txEvent = new TestTransactionEvent()
      .setFrom(mockTxFrom)
      .setBlock(10)
      .setHash("0x1")
      .addEventLog(transferEvent, TEST_TOKEN, data);

    when(mockFetcher.getValueInUsd)
      .calledWith(1, "3424324324423423", TEST_TOKEN)
      .mockReturnValue(69999);

    const findings = await handleTransaction(txEvent);
    expect(findings).toStrictEqual([
      testCreateFinding(
        TEST_TOKEN,
        "69999.00",
        "0x1",
        mockTxFrom,
        FindingSeverity.High,
        mockTxFrom
      ),
    ]);
  });

  it.only("should return a Medium severity finding if the usd value of the minted token is over $10000 and the mint recipient is a new EOA", async () => {
    const mockMintRecipient = createAddress("0x4321");
    const data = [
      createAddress("0x0"),
      mockMintRecipient,
      ethers.BigNumber.from("3424324324423423"),
    ];

    const txEvent = new TestTransactionEvent()
      .setFrom(mockTxFrom)
      .setBlock(10)
      .setHash("0x1")
      .addEventLog(transferEvent, TEST_TOKEN, data);

    when(mockFetcher.getValueInUsd)
      .calledWith(1, "3424324324423423", TEST_TOKEN)
      .mockReturnValue(12000);

    mockProvider.setCode(mockMintRecipient, "0x", 10);
    mockProvider.setNonce(mockMintRecipient, 9, 0);

    const findings = await handleTransaction(txEvent);
    expect(findings).toStrictEqual([
      testCreateFinding(
        TEST_TOKEN,
        "12000.00",
        "0x1",
        mockMintRecipient,
        FindingSeverity.Medium,
        mockTxFrom
      ),
    ]);
  });

  it.only("should return empty findings if the usd value of the minted token is known and under $10000, even if the mint recipient is a new EOA", async () => {
    const mockMintRecipient = createAddress("0x4321");
    const data = [
      createAddress("0x0"),
      mockMintRecipient,
      ethers.BigNumber.from("3424324324423423"),
    ];

    const txEvent = new TestTransactionEvent()
      .setFrom(mockTxFrom)
      .setBlock(10)
      .setHash("0x1")
      .addEventLog(transferEvent, TEST_TOKEN, data);

    when(mockFetcher.getValueInUsd)
      .calledWith(1, "3424324324423423", TEST_TOKEN)
      .mockReturnValue(9000); // Under threshold

    mockProvider.setCode(mockMintRecipient, "0x", 10);

    const findings = await handleTransaction(txEvent);
    expect(findings).toStrictEqual([]);
  });

  it.only("should return an Info severity finding if the usd value of the minted token is unknown and the mint recipient is a new EOA", async () => {
    const mockMintRecipient = createAddress("0x4321");
    const data = [
      createAddress("0x0"),
      mockMintRecipient,
      ethers.BigNumber.from("3424324324423423"),
    ];

    const txEvent = new TestTransactionEvent()
      .setFrom(mockTxFrom)
      .setBlock(10)
      .setHash("0x1")
      .addEventLog(transferEvent, TEST_TOKEN, data);

    when(mockFetcher.getValueInUsd)
      .calledWith(1, "3424324324423423", TEST_TOKEN)
      .mockReturnValue(0); // Unknown

    mockProvider.setCode(mockMintRecipient, "0x", 10);
    mockProvider.setNonce(mockMintRecipient, 9, 0);

    const findings = await handleTransaction(txEvent);
    expect(findings).toStrictEqual([
      testCreateFinding(
        TEST_TOKEN,
        "0.00",
        "0x1",
        mockMintRecipient,
        FindingSeverity.Info,
        mockTxFrom
      ),
    ]);
  });
});
