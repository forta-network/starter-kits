import { Finding, FindingSeverity, FindingType, Label, EntityType } from "forta-agent";
import { utils } from "ethers";
import { MockAsset, MockAssetDetails } from "./mock.types";

export function createMockBlockedAssetFinding(asset: MockAsset, assetDetails: MockAssetDetails): Finding {
  const { content, type, status, updatedAt }: MockAsset = asset;
  const { reason, reportId, reportUrl }: MockAssetDetails = assetDetails;

  const resultString: string = content + updatedAt;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: "A scam has been detected by ChainPatrol",
    description: `ChainPatrol detected scam: ${content}`,
    alertId: "CHAINPATROL-SCAM-ASSET",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    uniqueKey,
    protocol: "N/A",
    metadata: {
      type,
      status,
      updatedAt,
      reason: reason ? reason : "",
      reportId: reportId ? reportId.toString() : "",
      reportUrl: reportUrl ? reportUrl : "",
      Url: content,
    },
    labels: [
      Label.fromObject({
        entity: content,
        entityType: EntityType.Url,
        label: `Blocked ${type}`,
        confidence: 0.99,
        remove: false,
        metadata: {
          type,
          status,
          updatedAt,
          reason: reason ? reason : "",
          reportId: reportId ? reportId.toString() : "",
          reportUrl: reportUrl ? reportUrl : "",
        },
      }),
    ],
  });
}

export function createMockBlockedAssetFindingBatch(assets: MockAsset[], assetDetails: MockAssetDetails[]): Finding[] {
  const findings: Finding[] = [];

  if (assets.length === assetDetails.length) {
    for (let i = 0; i < assets.length; i++) {
      findings.push(createMockBlockedAssetFinding(assets[i], assetDetails[i]));
    }
  }

  return findings;
}
