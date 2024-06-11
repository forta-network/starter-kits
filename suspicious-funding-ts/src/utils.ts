import {
  EntityType,
  Finding,
  FindingSeverity,
  FindingType,
  Label,
  LabelCursor,
  LabelQueryOptions,
  LabelsResponse,
  getLabels,
} from "forta-agent";
import { alertOriginMap } from "./constants";

export const getAllLabels = async (
  query: LabelQueryOptions,
  attackers: Map<string, { origin: string; hops: number }>
) => {
  let startingCursor: LabelCursor | undefined;
  let labelsResponse: LabelsResponse;
  do {
    labelsResponse = await getLabels({ ...query, startingCursor });
    for (const label of labelsResponse.labels) {
      const alertId = label.source?.alertId;

      // Exclude "FUNDING-TORNADO-CASH-HIGH" and "...-LOW-AMOUNT" alerts
      if (alertId && !alertId.includes("HIGH") && !alertId.includes("LOW")) {
        let origin = "Unknown Origin";
        let hops = 0;

        for (const [key, value] of Object.entries(alertOriginMap)) {
          if (alertId.includes(key)) {
            origin = value;
            break;
          }
        }

        if (alertId.includes("SUSPICIOUS-FUNDING") || alertId.includes("MALICIOUS-FUNDING")) {
          if (label.metadata.origin && label.metadata.hops) {
            origin = label.metadata.origin;
            hops = parseInt(label.metadata.hops, 10);
          } else continue;
        }
        attackers.set(label.entity.toLowerCase(), { origin, hops });
      }
    }

    startingCursor = labelsResponse.pageInfo.endCursor;
  } while (labelsResponse.pageInfo.hasNextPage);
};

export const createFinding = (
  from: string,
  to: string,
  origin: string,
  hops: number
): Finding => {
  return Finding.fromObject({
    name: origin == "True Positive List" ? "Malicious Funding Alert" : "Suspicious Funding Alert",
    description: `${to} received funds from ${from}`,
    alertId: origin == "True Positive List" ? "MALICIOUS-FUNDING" : "SUSPICIOUS-FUNDING",
    severity: origin == "True Positive List" ? FindingSeverity.Critical : FindingSeverity.Medium,
    type: origin == "True Positive List" ? FindingType.Exploit : FindingType.Suspicious,
    metadata: {
      sender: from,
      receiver: to,
      origin,
      hops: hops.toString(),
    },
    labels: [
      Label.fromObject({
        entity: to,
        entityType: EntityType.Address,
        label: "attacker",
        confidence: origin == "True Positive List" ? 1.0 : 0.6,
        remove: false,
        metadata: {
          origin,
          hops: hops.toString(),
        },
      }),
    ],
  });
};
