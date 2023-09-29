import { when } from "jest-when";
import { MockApiOptions, MockAsset, MockAssetDetails } from "./mocks/mock.types";
import {
  createMockAssetsBatchFromMockAssetListBatch,
  createMockAssetDetailsApiOptions,
  createMockAssetListApiOptions,
  createMockAssetDetailsBatch,
  createMockAssetListBatch,
  createMockAssetBatch,
} from "./mocks/mock.utils";
import AssetFetcher from "./fetcher";

describe("AssetFetcher Test Suite", () => {
  const mockApiKey = "mockKey";
  const mockAssetListUrl = "MockAssetListUrl";
  const mockAssetDetailsUrl = "mockAssetDetailsUrl";
  const mockAssetBlockedStatus = "BLOCKED";
  const mockStartDate = "2022-09-15";
  const mockEndDate = "2023-09-15";
  const mockAssetTypes = ["URL", "PAGE", "TWITTER"];
  let fetcher: AssetFetcher;

  beforeAll(() => {
    fetcher = new AssetFetcher(mockApiKey, mockAssetListUrl, mockAssetDetailsUrl, mockAssetBlockedStatus);
  });

  it("should fetch AssetList with retries", async () => {
    global.fetch = jest.fn();

    const assetListBatchOfThree = 3;
    const oneAssetPerAssetList = 1;
    const mockAssetListOfThree = createMockAssetListBatch(assetListBatchOfThree, oneAssetPerAssetList);
    const mockAssetsFromMockAssetListOfThree = createMockAssetsBatchFromMockAssetListBatch(mockAssetListOfThree);

    const mockApiOptions: MockApiOptions[] = [];
    mockAssetTypes.map((type: string) => {
      mockApiOptions.push(
        createMockAssetListApiOptions(mockApiKey, type, mockAssetBlockedStatus, mockEndDate, mockStartDate)
      );
    });

    mockApiOptions.map((mockOptions: MockApiOptions, i: number) => {
      when(global.fetch)
        .calledWith(mockAssetListUrl, mockOptions)
        .mockRejectedValueOnce(new Error("First fetch intentionally failed"))
        .mockReturnValue(
          Promise.resolve({
            json: () => Promise.resolve(mockAssetListOfThree[i]),
          }) as Promise<Response>
        );
    });

    const assetList = await fetcher.getAssetlist(mockEndDate, mockStartDate);
    console.log(`assetList: ${JSON.stringify(assetList)}`);
    console.log(`mockAssetsFromMockAssetListOfThree: ${JSON.stringify(mockAssetsFromMockAssetListOfThree)}`);
    expect(assetList).toStrictEqual(mockAssetsFromMockAssetListOfThree);
    // 6 calls: 3 different calls, with each failing once before succeding.
    expect(global.fetch).toHaveBeenCalledTimes(6);

    const cachedAssetList = await fetcher.getAssetlist(mockEndDate, mockStartDate);
    expect(cachedAssetList).toStrictEqual(mockAssetsFromMockAssetListOfThree);
    expect(global.fetch).toHaveBeenCalledTimes(6); // No extra calls, cached value used
  });

  it("should fetch AssetDetails with retries", async () => {
    global.fetch = jest.fn();

    const batchOfThree = 3;
    const mockAssetBatchOfThree = createMockAssetBatch(batchOfThree);
    const mockAssetDetailsBatchOfThree = createMockAssetDetailsBatch(batchOfThree);

    const mockApiOptions: MockApiOptions[] = [];
    mockAssetBatchOfThree.map((asset: MockAsset) => {
      mockApiOptions.push(createMockAssetDetailsApiOptions(mockApiKey, asset.content));
    });

    mockApiOptions.map((mockOptions: MockApiOptions, i: number) => {
      when(global.fetch)
        .calledWith(mockAssetDetailsUrl, mockOptions)
        .mockRejectedValueOnce(new Error("First fetch intentionally failed"))
        .mockReturnValue(
          Promise.resolve({
            json: () => Promise.resolve(mockAssetDetailsBatchOfThree[i]),
          }) as Promise<Response>
        );
    });

    const assetDetails: MockAssetDetails[] = [];
    await Promise.all(
      mockAssetBatchOfThree.map(async (asset: MockAsset) => {
        assetDetails.push((await fetcher.getAssetDetails(asset.content))!);
      })
    );

    expect(assetDetails).toStrictEqual(mockAssetDetailsBatchOfThree);
    // 6 calls: 3 different calls, with each failing once before succeding.
    expect(global.fetch).toHaveBeenCalledTimes(6);

    const cachedAssetDetails: MockAssetDetails[] = [];
    await Promise.all(
      mockAssetBatchOfThree.map(async (asset: MockAsset) => {
        cachedAssetDetails.push((await fetcher.getAssetDetails(asset.content))!);
      })
    );
    expect(cachedAssetDetails).toStrictEqual(mockAssetDetailsBatchOfThree);
    expect(global.fetch).toHaveBeenCalledTimes(6); // No extra calls, cached value used
  });
});
