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

export const getAllLabels = async (
  query: LabelQueryOptions,
  attackers: Set<string>
) => {
  let startingCursor: LabelCursor | undefined;
  let labelsResponse: LabelsResponse;
  do {
    labelsResponse = await getLabels({ ...query, startingCursor });
    labelsResponse.labels.forEach((label) => {
      // Exclude "FUNDING-TORNADO-CASH-HIGH" and "...-LOW-AMOUNT" alerts
      if (
        !label.source?.alertId?.includes("HIGH") &&
        !label.source?.alertId?.includes("LOW")
      ) {
        attackers.add(label.entity.toLowerCase());
      }
    });
    startingCursor = labelsResponse.pageInfo.endCursor;
  } while (labelsResponse.pageInfo.hasNextPage);
};

export const createFinding = (from: string, to: string): Finding => {
  return Finding.fromObject({
    name: "Suspicious Funding Alert",
    description: `${to} received funds from ${from}`,
    alertId: "SUSPICIOUS-FUNDING",
    severity: FindingSeverity.Medium,
    type: FindingType.Suspicious,
    metadata: {
      sender: from,
      receiver: to,
    },
    labels: [
      Label.fromObject({
        entity: to,
        entityType: EntityType.Address,
        label: "attacker",
        confidence: 0.6,
        remove: false,
      }),
    ],
  });
};
