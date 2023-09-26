import { MockAsset, MockAssetDetails } from "./mock.types";
import { createMockBlockedAssetFinding } from "./mock.findings";

function createMockAssetInstance(instanceIndex: number): MockAsset {
  return {
    content: `mockContent${instanceIndex}`,
    type: `mockType${instanceIndex}`,
    status: `mockStatus${instanceIndex}`,
    updatedAt: `2022-09-15T12:00:00.${String(instanceIndex).padStart(3, "0")}Z`,
  };
}

export function createMockAssetListBatch(amountInBatch: number): MockAsset[] {
  const mockAssetListBatch: MockAsset[] = [];

  for (let i = 1; i <= amountInBatch; i++) {
    mockAssetListBatch.push(createMockAssetInstance(i));
  }

  return mockAssetListBatch;
}

function createMockAssetDetailsInstance(instanceIndex: number): MockAssetDetails {
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
