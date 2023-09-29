export type MockApiKeys = {
  apiKeys: {
    CHAINPATROL: string;
  };
};

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

type MockHeaders = {
  "X-API-KEY": string;
  "Content-Type": string;
};

export type MockApiOptions = {
  method: string;
  headers: MockHeaders;
  body: string;
};
