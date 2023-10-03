import { Initialize, HandleBlock } from "forta-agent";
import { TestBlockEvent } from "forta-agent-tools/lib/test";
import { when } from "jest-when";
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
});
