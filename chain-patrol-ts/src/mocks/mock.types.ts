export type MockAsset = {
  content: string;
  type: string;
  status: string;
  updatedAt: string;
};

export type MockAssetList = {
  assets: MockAsset[];
};

export type MockAssetDetails = {
  status: string;
  reason?: string;
  reportId?: number;
  reportUrl?: string;
};
