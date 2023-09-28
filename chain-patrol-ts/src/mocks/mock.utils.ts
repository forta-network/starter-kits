import { MockAsset, MockAssetList, MockAssetDetails, MockApiOptions } from "./mock.types";

function createMockAssetInstance(instanceIndex: number): MockAsset {
  return {
    content: `mockContent${instanceIndex}`,
    type: `mockType${instanceIndex}`,
    status: `mockStatus${instanceIndex}`,
    updatedAt: `2022-09-15T12:00:00.${String(instanceIndex).padStart(3, "0")}Z`,
  };
}

export function createMockAssetBatch(amountInBatch: number): MockAsset[] {
  const mockAssetBatch: MockAsset[] = [];

  for (let i = 1; i <= amountInBatch; i++) {
    mockAssetBatch.push(createMockAssetInstance(i));
  }

  return mockAssetBatch;
}

function createMockAssetListInstance(assetsAmount: number): MockAssetList {
  const mockAssetListInstance: MockAssetList = { assets: [] };

  for (let i = 1; i <= assetsAmount; i++) {
    mockAssetListInstance.assets.push(createMockAssetInstance(Math.floor(Math.random() * 1000)));
  }

  return mockAssetListInstance;
}

export function createMockAssetListBatch(amountInBatch: number, assetsPerInstance: number): MockAssetList[] {
  const mockAssetListBatch: MockAssetList[] = [];

  for (let i = 1; i <= amountInBatch; i++) {
    mockAssetListBatch.push(createMockAssetListInstance(assetsPerInstance));
  }

  return mockAssetListBatch;
}

export function createMockAssetDetailsInstance(instanceIndex: number): MockAssetDetails {
  return {
    status: `mockStatus${instanceIndex}`,
    reason: `mockReason${instanceIndex}`,
    reportId: 1000 + instanceIndex,
    reportUrl: `mockReportUrl${instanceIndex}`,
  };
}

export function createMockAssetDetailsBatch(amountInBatch: number): MockAssetDetails[] {
  const mockAssetDetailsBatch: MockAssetDetails[] = [];

  for (let i = 1; i <= amountInBatch; i++) {
    mockAssetDetailsBatch.push(createMockAssetDetailsInstance(i));
  }

  return mockAssetDetailsBatch;
}

export function createMockAssetListApiOptions(
  apiKey: string,
  type: string,
  status: string,
  endDate: string,
  startDate: string
): MockApiOptions {
  return {
    method: "POST",
    headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
    body: `{"type":"${type}","status":"${status}","endDate":"${endDate}","startDate":"${startDate}"}`,
  };
}

export function createMockAssetDetailsApiOptions(apiKey: string, assetContent: string): MockApiOptions {
  return {
    method: "POST",
    headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
    body: `{"content":"${assetContent}"}`,
  };
}

export function createMockAssetsBatchFromMockAssetListBatch(mockAssetListBatch: MockAssetList[]): MockAsset[] {
  const mockAssetBatch: MockAsset[] = [];

  for (let i = 0; i < mockAssetListBatch.length; i++) {
    for (let j = 0; j < mockAssetListBatch[i].assets.length; j++) {
      mockAssetBatch.push(mockAssetListBatch[i].assets[j]);
    }
  }

  return mockAssetBatch;
}
