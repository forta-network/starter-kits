import { Finding, FindingSeverity, FindingType, Label, EntityType } from "forta-agent";
import { utils } from "ethers";

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
  reason: string;
  reportId: number;
  reportUrl: string;
};

export function createMockFinding(asset: MockAsset, assetDetails: MockAssetDetails): Finding {
  const { content, type, status, updatedAt }: MockAsset = asset;
  const { reason, reportId, reportUrl }: MockAssetDetails = assetDetails;

  const resultString: string = content + reason + reportId + reportUrl + updatedAt;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `ChainPatrol Blocklist item detected: ${content}`,
    description: "An item from ChainPatrol's Blocklist has been detected",
    alertId: "BLOCKED-CHAINPATROL-ASSET",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    uniqueKey,
    metadata: {
      type,
      status,
      updatedAt,
      reason,
      reportId: reportId.toString(),
      reportUrl,
    },
    labels: [
      Label.fromObject({
        entity: content,
        entityType: EntityType.Url,
        label: `Blocked ${type}`,
        confidence: 0.99, // TODO: Figure out the appropriate value to use
        remove: false,
        metadata: {
          type,
          status,
          updatedAt,
          reason,
          reportId: reportId.toString(),
          reportUrl,
        },
      }),
    ],
  });
}
