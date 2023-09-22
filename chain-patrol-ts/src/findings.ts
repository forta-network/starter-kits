import { ApiOptions, AssetList, Asset, AssetDetails } from "./types";
import { Finding, FindingSeverity, FindingType, Label, EntityType } from "forta-agent";

export function createFinding(asset: Asset, assetDetails: AssetDetails): Finding {
  const { content, type, status, updatedAt }: Asset = asset;
  const { reason, reportId, reportUrl }: AssetDetails = assetDetails;
  /*
  const resultString: string = chain_id + address + deployer_addr + name + symbol + created_at;
  const uniqueKey: string = utils.keccak256(utils.toUtf8Bytes(resultString));
  */

  return Finding.fromObject({
    name: `ChainPatrol Blocklist item detected: ${content}`,
    description: "An item from ChainPatrol's Blocklist has been detected",
    alertId: "BLOCKED-CHAINPATROL-ASSET",
    severity: FindingSeverity.Critical,
    type: FindingType.Scam,
    // uniqueKey, // Utilize the blocked item's `updatedAt` property to generate
    // TODO: Make sure below properties _are_ optional
    // source: { chains: [{ chainId: Number(chain_id) }] },
    // addresses: []
    // protocol:
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
