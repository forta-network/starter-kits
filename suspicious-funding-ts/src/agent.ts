import {
  Finding,
  HandleAlert,
  AlertEvent,
  TransactionEvent,
  LabelQueryOptions,
  ethers,
  getEthersProvider,
} from "forta-agent";
import {
  BOTS_TO_MONITOR,
  DAYS_TO_LOOK_BACK,
  VALUE_THRESHOLDS,
  alertOriginMap,
} from "./constants";
import { createFinding, getAllLabels } from "./utils";

const ethersProvider = getEthersProvider();
const attackers = new Map<string, { origin: string; hops: number }>();
let chainId: number;

export const provideInitialize =
  (provider: ethers.providers.Provider) => async () => {
    chainId = Number((await provider.getNetwork()).chainId);

    const query: LabelQueryOptions = {
      sourceIds: BOTS_TO_MONITOR,
      state: true,
      labels: ["attacker"],
      createdSince: Date.now() - DAYS_TO_LOOK_BACK * 60 * 60 * 24 * 1000,
      first: 2000,
    };
    await getAllLabels(query, attackers);

    return {
      alertConfig: {
        subscriptions: [
          {
            botId: BOTS_TO_MONITOR[0],
            alertIds: ["FUNDING-TORNADO-CASH"],
          },
          {
            botId: BOTS_TO_MONITOR[1],
            alertIds: ["FUNDING-FIXED-FLOAT-NEW-ACCOUNT"],
          },
          {
            botId: BOTS_TO_MONITOR[2],
            alertIds: ["EARLY-ATTACK-DETECTOR-1"],
          },
        ],
      },
    };
  };

export const provideHandleTransaction =
  (
    attackers: Map<string, { origin: string; hops: number }>,
    provider: ethers.providers.Provider
  ) =>
  async (txEvent: TransactionEvent) => {
    const findings: Finding[] = [];

    if (
      txEvent.to &&
      attackers.has(txEvent.from.toLowerCase()) &&
      txEvent.transaction.value != "0x0" &&
      Number(txEvent.transaction.value) / 1e18 <= VALUE_THRESHOLDS[chainId]
    ) {
      if (
        (await provider.getTransactionCount(txEvent.to)) === 0 &&
        (await provider.getCode(txEvent.to)) === "0x"
      ) {
        const senderInfo = attackers.get(txEvent.from.toLowerCase());
        if (senderInfo) {
          const newHops = senderInfo.hops + 1;
          attackers.set(txEvent.to.toLowerCase(), {
            origin: senderInfo.origin,
            hops: newHops,
          });
          findings.push(
            createFinding(txEvent.from, txEvent.to, senderInfo.origin, newHops)
          );
        }
      }
    }

    return findings;
  };

const handleAlert: HandleAlert = async (alertEvent: AlertEvent) => {
  const findings: Finding[] = [];

  alertEvent.alert.labels?.forEach((label) => {
    if (label.label === "attacker") {
      let origin = "Unknown Origin";
      const alertId = alertEvent.alert.alertId;

      for (const [key, value] of Object.entries(alertOriginMap)) {
        if (alertId?.includes(key)) {
          origin = value;
          break;
        }
      }

      attackers.set(label.entity.toLowerCase(), { origin, hops: 0 });
    }
  });
  return findings;
};

export default {
  initialize: provideInitialize(ethersProvider),
  handleTransaction: provideHandleTransaction(attackers, ethersProvider),
  handleAlert,
};
