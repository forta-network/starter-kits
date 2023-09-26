type Headers = {
  "X-API-KEY": string;
  "Content-Type": string;
};

export type ApiOptions = {
  method: string;
  headers: Headers;
  body: string;
};

export type Asset = {
  content: string;
  type: string;
  status: string;
  updatedAt: string;
};

export type AssetList = {
  assets: Asset[];
};

export type AssetDetails = {
  status: string;
  reason: string;
  reportId: number;
  reportUrl: string;
};

export type UnalertedAsset = {
  content: string;
  type: string;
  status: string;
  updatedAt: string;
  reason: string;
  reportId: number;
  reportUrl: string;
};
