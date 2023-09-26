import { FindingType, FindingSeverity, Finding, HandleBlock, ethers, Initialize } from "forta-agent";
import { TestBlockEvent } from "forta-agent-tools/lib/test";
import { when } from "jest-when";
import { provideInitialize, provideHandleBlock } from "./agent";
import AssetFetcher from "./fetcher";
import { MockAsset, MockAssetList, MockAssetDetails, createMockFinding } from "./mock.utils";


const mockEthereumBlocksInADay = 7200;
const mockInitApiQueryDate = "2022-09-15";
const mockApiKey = "mockKey";
const mockAssetListUrl = "MockAssetListUrl";
const mockAssetDetailsUrl = "mockAssetDetailsUrl";
const mockAssetBlockedStatus = "BLOCKED";
const mockAssetList: MockAsset[] = [
  {
    content: "mockContent",
    type: "mockType",
    status: "mockStatus",
    updatedAt: "mockUpdatedAt",
  },
];
const mockAssetDetails: MockAssetDetails = {
  status: "mockStatus",
  reason: "mockReason",
  reportId: 11,
  reportUrl: "mockReportUrl",
};

describe("ChainPatrol Bot Test Suite", () => {
  const mockBlockEvent = new TestBlockEvent().setNumber(mockEthereumBlocksInADay);

  async function mockApiFetcher(): Promise<string> {
    return mockApiKey;
  }

  const mockAssetFetcher = {
    getAssetlist: jest.fn(),
    getAssetDetails: jest.fn(),
  };

  const mockCurrentDateFetcher = jest.fn();

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
      mockAssetFetcherCreator,
      mockInitApiQueryDate
    );
    await initialize();

    handleBlock = provideHandleBlock(mockCurrentDateFetcher as any);
  });

  it.only("creates alerts when the API sends data", async () => {
    const mockCurrentDate = "2023-09-25";
    when(mockCurrentDateFetcher).calledWith().mockReturnValue(mockCurrentDate);
    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockAssetBlockedStatus, mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetList);
    when(mockAssetFetcher.getAssetDetails)
      .calledWith(mockAssetList[0].content)
      .mockReturnValue(mockAssetDetails);

    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([createMockFinding(mockAssetList[0], mockAssetDetails)]);
  });

  it("creates no alerts if getAssetList returns empty array", async () => {
  });

  it("creates no alerts if getAssetDetails returns empty array", async () => {});

  it("creates numerous alerts if the API query returns numerous results", async () => {});

  it("creates alerts up until the limit and creates alerts for the rest in subsequent blocks", async () => {});

  it("creates alerts up to the 50 alert limit then creates the rest in the subsequent block", async () => {});
});
