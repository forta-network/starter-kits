import { FindingType, FindingSeverity, Finding, HandleBlock, ethers, Initialize } from "forta-agent";
import { TestBlockEvent } from "forta-agent-tools/lib/test";
import { when } from "jest-when";
import { provideInitialize, provideHandleBlock } from "./agent";
import AssetFetcher from "./fetcher";
import { MockAsset, MockAssetList, MockAssetDetails, createMockFinding } from "./mock.utils";

describe("ChainPatrol Bot Test Suite", () => {
  const mockEthereumBlocksInADay = 7200;
  const mockBlockEvent = new TestBlockEvent().setNumber(mockEthereumBlocksInADay);
  const mockInitApiQueryDate = "2022-09-15";
  const mockCurrentDate = "2023-09-25";
  const mockApiKey = "mockKey";

  async function mockApiFetcher(): Promise<string> {
    return mockApiKey;
  }
  const mockAssetListUrl = "MockAssetListUrl";
  const mockAssetDetailsUrl = "mockAssetDetailsUrl";

  const mockAssetBlockedStatus = "BLOCKED";

  const mockAssetList: MockAssetList = {
    assets: [
      {
        content: "mockContent",
        type: "mockType",
        status: "mockStatus",
        updatedAt: "mockUpdatedAt",
      },
    ],
  };

  const mockAssetDetails: MockAssetDetails = {
    status: "mockStatus",
    reason: "mockReason",
    reportId: 11,
    reportUrl: "mockReportUrl",
  };

  const mockAssetFetcher = {
    getAssetlist: jest.fn(),
    getAssetDetails: jest.fn(),
  };

  const mockCurrentDateFetcher = jest.fn();

  async function mockAssetFetcherCreator(
    apiFetcher: () => Promise<string>,
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

    when(mockCurrentDateFetcher).calledWith().mockReturnValue(mockCurrentDate);
    when(mockAssetFetcher.getAssetlist)
      .calledWith(mockAssetBlockedStatus, mockCurrentDate, mockInitApiQueryDate)
      .mockReturnValue(mockAssetList);
    when(mockAssetFetcher.getAssetDetails)
      .calledWith(mockAssetList.assets[0].content)
      .mockReturnValue(mockAssetDetails);
  });

  it("creates alerts when the API sends data", async () => {
    let findings = await handleBlock(mockBlockEvent);
    expect(findings).toStrictEqual([createMockFinding(mockAssetList.assets[0], mockAssetDetails)]);
  });
});
