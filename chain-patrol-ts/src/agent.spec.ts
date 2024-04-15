import { Initialize, HandleBlock } from "forta-agent";
import { TestBlockEvent } from "forta-agent-tools/lib/test";
import { when, resetAllWhenMocks } from "jest-when";
import { createMockBlockedAssetFinding, createMockBlockedAssetFindingBatch } from "./mocks/mock.findings";
import { MockApiKeys, MockAsset, MockAssetDetails } from "./mocks/mock.types";
import { provideInitialize, provideHandleBlock } from "./agent";
import {
  getMockDateFourWeeksAgoInYyyyMmDD,
  createMockAssetDetailsInstance,
  getMockCurrentDateInYyyyMmDD,
  createMockAssetDetailsBatch,
  createMockAssetBatch,
} from "./mocks/mock.utils";
import AssetFetcher from "./fetcher";

const mockEthereumBlocksInADay = 7200;
const mockInitApiQueryDate = getMockDateFourWeeksAgoInYyyyMmDD();
const mockCurrentDate = getMockCurrentDateInYyyyMmDD();
const mockApiKey = "mockKey";
const mockAssetListUrl = "MockAssetListUrl";
const mockAssetDetailsUrl = "mockAssetDetailsUrl";
const batchOfOne = 1;
const mockAssetList = createMockAssetBatch(batchOfOne);
const mockAssetDetails = createMockAssetDetailsInstance(batchOfOne);

describe("ChainPatrol Bot Test Suite", () => {
  const mockBlockEvent = new TestBlockEvent().setNumber(mockEthereumBlocksInADay);

  async function mockApiFetcher(): Promise<MockApiKeys> {
    return { apiKeys: { CHAINPATROL: mockApiKey } };
  }

  const mockAssetFetcher = {
    getAssetlist: jest.fn(),
    getAssetDetails: jest.fn(),
  };

  async function mockAssetFetcherCreator(
    apiKey: string,
    assetListUrl: string,
    assetDetailsUrl: string
  ): Promise<AssetFetcher> {
    return mockAssetFetcher as any;
  }

  let handleBlock: HandleBlock;

  beforeEach(async () => {
    resetAllWhenMocks();

    const initialize: Initialize = provideInitialize(
      mockApiFetcher,
      mockAssetListUrl,
      mockAssetDetailsUrl,
      mockAssetFetcherCreator
    );
    await initialize();

    handleBlock = provideHandleBlock();
  });

  it("creates alerts when the API sends data", async () => {
    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetList);
    when(mockAssetFetcher.getAssetDetails).calledWith(mockAssetList[0].content).mockReturnValue(mockAssetDetails);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([createMockBlockedAssetFinding(mockAssetList[0], mockAssetDetails)]);
  });

  it("creates no alerts if getAssetList returns empty array of Assets", async () => {
    const mockAssetList: MockAsset[] = [];

    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetList);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([]);
  });

  it("creates an alert despite getAssetDetails returning 'UNKNOWN'", async () => {
    const mockAssetDetails: MockAssetDetails = {
      status: "mockUNKNOWN",
    };

    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetList);
    when(mockAssetFetcher.getAssetDetails).calledWith(mockAssetList[0].content).mockReturnValue(mockAssetDetails);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([createMockBlockedAssetFinding(mockAssetList[0], mockAssetDetails)]);
  });

  it("creates multiple alerts if the API query returns multiple results", async () => {
    const batchOfFive = 5;
    const mockAssetListOfFive = createMockAssetBatch(batchOfFive);
    const mockAssetDetailsOfFive = createMockAssetDetailsBatch(batchOfFive);
    const mockFindings = createMockBlockedAssetFindingBatch(mockAssetListOfFive, mockAssetDetailsOfFive);

    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetListOfFive);
    mockAssetListOfFive.map((mockAsset: MockAsset, i: number) => {
      when(mockAssetFetcher.getAssetDetails).calledWith(mockAsset.content).mockReturnValue(mockAssetDetailsOfFive[i]);
    });

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(mockFindings);
  });

  it("correctly handles receiving some 'UNKNOWN' statuses mixed with getAssetDetails payload", async () => {
    const batchOfSeven = 7;
    const mockAssetListOfSeven = createMockAssetBatch(batchOfSeven);
    const mockAssetDetailsOfSeven = createMockAssetDetailsBatch(batchOfSeven);

    const mockAssetDetails: MockAssetDetails = {
      status: "mockUNKNOWN",
    };

    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetListOfSeven);
    mockAssetListOfSeven.map((mockAsset: MockAsset, i: number) => {
      if (i === 3 || i === 4) {
        // Overwrite to be of status `UNKNOWN`
        mockAssetDetailsOfSeven[i] = mockAssetDetails;
        when(mockAssetFetcher.getAssetDetails).calledWith(mockAsset.content).mockReturnValue(mockAssetDetails);
      } else {
        when(mockAssetFetcher.getAssetDetails)
          .calledWith(mockAsset.content)
          .mockReturnValue(mockAssetDetailsOfSeven[i]);
      }
    });

    const mockFindings = createMockBlockedAssetFindingBatch(mockAssetListOfSeven, mockAssetDetailsOfSeven);
    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(mockFindings);
  });

  it("creates alerts up to the 50 alert limit then creates the rest in the subsequent block", async () => {
    const batchOfSixtyFive = 65;
    const mockAssetListOfSixtyFive = createMockAssetBatch(batchOfSixtyFive);
    const mockAssetDetailsOfSixtyFive = createMockAssetDetailsBatch(batchOfSixtyFive);
    const mockFindings = createMockBlockedAssetFindingBatch(mockAssetListOfSixtyFive, mockAssetDetailsOfSixtyFive);

    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetListOfSixtyFive);
    mockAssetListOfSixtyFive.map((mockAsset: MockAsset, i: number) => {
      when(mockAssetFetcher.getAssetDetails)
        .calledWith(mockAsset.content)
        .mockReturnValue(mockAssetDetailsOfSixtyFive[i]);
    });

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(mockFindings.slice(0, 50));

    // Create alerts in the very next block
    mockBlockEvent.setNumber(mockEthereumBlocksInADay + 1);
    findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(mockFindings.slice(50));
  });

  it("creates alerts when bot is freshly deployed even if block number does not mark a day in Ethereum block time, but not in subsequent block", async () => {
    const batchOfThree = 3;
    const mockAssetListOfThree = createMockAssetBatch(batchOfThree);
    const mockAssetDetailsOfThree = createMockAssetDetailsBatch(batchOfThree);
    const mockFindings = createMockBlockedAssetFindingBatch(mockAssetListOfThree, mockAssetDetailsOfThree);

    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetListOfThree);
    mockAssetListOfThree.map((mockAsset: MockAsset, i: number) => {
      when(mockAssetFetcher.getAssetDetails).calledWith(mockAsset.content).mockReturnValue(mockAssetDetailsOfThree[i]);
    });

    const nonDayInEthereumBlockNumber = 10;
    mockBlockEvent.setNumber(nonDayInEthereumBlockNumber);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(mockFindings);

    // Using `mockCurrentDate` as argument twice since it would
    // be updated in the bots logic. Setting this `when` to confirm
    // _something_ would return, and the bot will still not create alerts
    // because it would not be a block number that is divisible by
    // `ETHEREUM_BLOCKS_IN_ONE_DAY` and `hasCreatedAlertsUponDeployment`
    // would now be set to `true`.
    when(mockAssetFetcher.getAssetlist).calledWith(mockCurrentDate, mockCurrentDate).mockReturnValue(mockAssetList);
    when(mockAssetFetcher.getAssetDetails).calledWith(mockAssetList[0].content).mockReturnValue(mockAssetDetails);

    mockBlockEvent.setNumber(nonDayInEthereumBlockNumber + 1);
    findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([]);
  });

  it("creates an alert for an asset that was fetched, but its details were only fetched after first returning 'undefined'", async () => {
    const batchOfFive = 5;
    const mockAssetListOfFive = createMockAssetBatch(batchOfFive);
    const mockAssetDetailsOfFive = createMockAssetDetailsBatch(batchOfFive);

    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetListOfFive);

    mockAssetListOfFive.map((mockAsset: MockAsset, i: number) => {
      if (i < mockAssetListOfFive.length - 1) {
        when(mockAssetFetcher.getAssetDetails).calledWith(mockAsset.content).mockReturnValue(mockAssetDetailsOfFive[i]);
      } else {
        when(mockAssetFetcher.getAssetDetails).calledWith(mockAsset.content).mockReturnValue(undefined);
      }
    });

    let mockFindings = createMockBlockedAssetFindingBatch(
      mockAssetListOfFive.slice(0, -1),
      mockAssetDetailsOfFive.slice(0, -1)
    );

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(mockFindings);

    // Create alerts in the very next block
    mockBlockEvent.setNumber(mockEthereumBlocksInADay + 1);

    when(mockAssetFetcher.getAssetDetails)
      .calledWith(mockAssetListOfFive[mockAssetListOfFive.length - 1].content)
      .mockReturnValue(mockAssetDetailsOfFive[mockAssetDetailsOfFive.length - 1]);

    mockFindings = createMockBlockedAssetFindingBatch(
      [mockAssetListOfFive[mockAssetListOfFive.length - 1]],
      [mockAssetDetailsOfFive[mockAssetDetailsOfFive.length - 1]]
    );

    findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual(mockFindings);
  });
});
