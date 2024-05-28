import {
  EntityType,
  Finding,
  FindingSeverity,
  FindingType,
  Label,
} from "forta-agent";

export const createFinding = (
  token: string,
  usdValue: string,
  txHash: string,
  mintRecipient: string,
  severity: FindingSeverity,
  txFrom: string
): Finding => {
  let labels: Label[] = [];
  let metadata: {
    [key: string]: string;
  } = {};
  metadata["initiator"] = txFrom;
  metadata["token"] = token;
  metadata["usdValue"] = usdValue;
  metadata["txHash"] = txHash;
  metadata["mintRecipient"] = mintRecipient;

  labels.push(
    Label.fromObject({
      entity: mintRecipient,
      entityType: EntityType.Address,
      label: "Attacker",
      confidence:
        severity === FindingSeverity.High
          ? 0.7
          : severity === FindingSeverity.Medium
          ? 0.6
          : 0.5,
      remove: false,
    })
  );

  labels.push(
    Label.fromObject({
      entity: txHash,
      entityType: EntityType.Transaction,
      label: "Attack",
      confidence:
        severity === FindingSeverity.High
          ? 0.7
          : severity === FindingSeverity.Medium
          ? 0.6
          : 0.5,
      remove: false,
    })
  );

  return Finding.fromObject({
    name: "Suspicious Mint",
    description:
      severity === FindingSeverity.High
        ? `Token mint of >$50k to ${mintRecipient} detected`
        : severity === FindingSeverity.Medium
        ? `Token mint of >$10k to new EOA ${mintRecipient} detected`
        : `Token mint of unknown value to new EOA ${mintRecipient} detected`,
    alertId:
      severity === FindingSeverity.High
        ? "SUSPICIOUS-MINT-1"
        : severity === FindingSeverity.Medium
        ? "SUSPICIOUS-MINT-2"
        : "SUSPICIOUS-MINT-3",
    severity,
    type: FindingType.Suspicious,
    metadata,
    labels,
  });
};
