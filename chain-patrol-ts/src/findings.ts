import { Finding, FindingSeverity, FindingType, Label, EntityType } from "forta-agent";
import { utils } from "ethers";
import { UnalertedAsset } from "./types";

export function createBlockedAssetFinding(asset: UnalertedAsset): Finding {
  const { content, type, status, updatedAt, reason, reportId, reportUrl }: UnalertedAsset = asset;

  const resultString: string = content + updatedAt;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));

  return Finding.fromObject({
    name: `ChainPatrol Blocklist item detected: ${content}`,
    description: "An item from ChainPatrol's Blocklist has been detected",
    alertId: "CHAINPATROL-BLOCKED-ASSET",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    uniqueKey,
    metadata: {
      type,
      status,
      updatedAt,
      reason: reason ? reason : "",
      reportId: reportId ? reportId.toString() : "",
      reportUrl: reportUrl ? reportUrl : "",
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
          reason: reason ? reason : "",
          reportId: reportId ? reportId.toString() : "",
          reportUrl: reportUrl ? reportUrl : "",
        },
      }),
    ],
  });
}
