import {
  Finding,
  TransactionEvent,
  FindingSeverity,
  FindingType,
  ethers,
  getEthersProvider,
  Label,
  EntityType,
} from "forta-agent";
import { secrets } from "./storage";

export type ExtractedData = {
  tokenName: string;
  action: string;
  entity: string;
};

export function extractData(text: string) {
  let info: any = {};

  // match and extract the token
  let tokenMatch = text.match(/Your token \((.*?)\)/);
  if (tokenMatch) {
    info["token"] = tokenMatch[1];
  }

  // match and extract the action
  let actionMatch = text.match(/Your token \(.*?\) has been (.*?) to/);
  if (actionMatch) {
    info["action"] = actionMatch[1];
  } else {
    info["action"] = "approved";
  }

  // match and extract the address
  let addressMatch = text.match(/(0x[a-fA-F0-9]{40})/);
  if (addressMatch) {
    info["address"] = addressMatch[1];
  }

  // check type
  if (text.includes("phishing attack")) {
    info["type"] = "phishing transfer";
  } else {
    info["type"] = "phishing approval";
  }

  // return the info object if it contains exactly four keys, otherwise return null
  return Object.keys(info).length === 4 ? info : null;
}

function isValidCharRatio(str: string) {
  const words = str.trim().split(/\s+/);

  if (words.length < 2) {
    return false;
  }

  const totalChars = str.length;
  const validChars = str.match(/[a-zA-Z0-9\s]/g);

  if (validChars) {
    const validCharRatio = validChars.length / totalChars;
    return validCharRatio > 0.7;
  }

  return false;
}

export function containsWords(txEvent: TransactionEvent): {
  isValid: boolean;
  text: string;
} {
  const inputData = txEvent.transaction.data;
  try {
    const decodedData = Buffer.from(inputData.slice(2), "hex").toString("utf8");

    const stop_symbol = [
      "�",
      "%",
      "}",
      "{",
      ">",
      "<",
      "|",
      "[",
      "^",
      ")",
      "Ҿ",
      "⻱",
      "΢",
      "",
      "Ĭ",
      "",
      "",
      "",
      "",
      "ҁ",
      "",
      "",
      "",
      "",
      "޺",
      "",
      "",
      "�",
      "",
      "",
      "",
      "",
      "",
      "",
      "§",
      "ҿ",
      "ҽ",
      "Ҽ",
      "һ",
      "Һ",
      "ҹ",
      "Ҹ",
      "ү",
      "ï",
      "½",
      "¿",
    ];

    // Check for null characters
    if (
      !isValidCharRatio(decodedData) ||
      decodedData.includes("\0") ||
      stop_symbol.some((e) => {
        decodedData.includes(e);
      })
    ) {
      return { isValid: false, text: "" };
    }
    const wordRegex = /[a-zA-Z]+/g;
    const wordMatches = decodedData.match(wordRegex) || [];

    // Check if the number of words is greater than or equal to 2
    if (wordMatches.length >= 2) {
      return { isValid: true, text: decodedData };
    } else {
      return { isValid: false, text: "" };
    }
  } catch (error) {
    console.log("Error decoding input data:", txEvent.hash);
    return { isValid: false, text: "" };
  }
}

export function logs(txEvent: TransactionEvent, state: boolean, msg: string) {
  if (state) {
    console.log(`[Success] ${msg}`);
  } else console.log(`[Error] ${msg}, tx: ${txEvent.hash}`);
}

export async function getAddressType(
  address: string,
  provider: ethers.providers.Provider
): Promise<"EOA" | "CONTRACT"> {
  const code = await provider.getCode(address);
  if (code === "0x") {
    return "EOA";
  } else {
    return "CONTRACT";
  }
}

async function getAddressName(
  provider: ethers.providers.Provider,
  address: string
): Promise<string> {
  const name = await provider.lookupAddress(address);
  return name || "";
}

interface EtherscanResponse {
  result: {
    contractCreator: string;
  }[];
}

type ChainInfo = {
  [key: number]: { baseUrl: string; apiKey: string };
};

async function getContractCreation(
  contractAddress: string,
  chainId: number,
  keys: secrets
): Promise<string> {
  const chainInfo: ChainInfo = {
    1: {
      baseUrl: "https://api.etherscan.io/api",
      apiKey: keys.apiKeys.ETHERSCAN_TOKEN,
    },
    56: {
      baseUrl: "https://api.bscscan.com/api",
      apiKey: keys.apiKeys.BSCSCAN_TOKEN,
    },
    137: {
      baseUrl: "https://api.polygonscan.com/api",
      apiKey: keys.apiKeys.POLYGONSCAN_TOKEN,
    },
  };

  const { baseUrl, apiKey } = chainInfo[chainId] || {};

  if (!baseUrl || !apiKey) {
    console.log(`Unsupported chainId: ${chainId}`);
    return "Not Found";
  }

  const queryParams = new URLSearchParams({
    module: "contract",
    action: "getcontractcreation",
    contractaddresses: contractAddress,
    apikey: apiKey,
  });

  try {
    const url = `${baseUrl}?${queryParams.toString()}`;
    const response = await fetch(url);

    if (!response.ok) {
      console.log(
        `Error fetching data: ${response.statusText} for ${contractAddress}`
      );
    }

    const data = (await response.json()) as EtherscanResponse;
    const contractCreator = data.result[0].contractCreator;
    return contractCreator || "Not Found";
  } catch (error) {
    console.log(`Error fetching data: ${error} for ${contractAddress}`);
    return "Not Found";
  }
}

type ScamAlertType = "EOA" | "CONTRACT" | "NEW_NOTIFIER" | "VICTIM";

export async function createScamNotifierAlert(
  alertType: ScamAlertType,
  txEvent: TransactionEvent,
  keys: secrets,
  extraInfo?: any,
  similarNotifiers?: { sharingAddress: string; sharedRecipients: string[] }
): Promise<Finding> {
  let description: string;
  let severity: FindingSeverity;
  let type: FindingType;
  let alertId: string;
  const provider: ethers.providers.JsonRpcProvider = getEthersProvider();
  const metadata: { [key: string]: string } = {};
  const scammerEoa = txEvent.to!;
  const scammerContract = scammerEoa;
  const notifierEoa = txEvent.from;
  const notifierName = await getAddressName(provider, notifierEoa);
  const chainId = (await provider.getNetwork()).chainId;
  const addresses = Object.keys(txEvent.addresses);
  const labels: Label[] = [];

  switch (alertType) {
    case "VICTIM":
      // ! scammerEoa is the victim in this case.
      description = `${notifierEoa}${notifierName} alerted ${scammerEoa} from a ${extraInfo.token} ${extraInfo.type} to ${extraInfo.address}`;
      severity = FindingSeverity.High;
      type = FindingType.Exploit;
      alertId = "VICTIM-NOTIFIER-EOA";
      metadata.victim_eoa = scammerEoa;
      metadata.scammer_eoa = extraInfo.address;
      metadata.notifier_eoa = notifierEoa;
      metadata.notifier_name = notifierName;
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: notifierEoa,
          label: "notifier_EOA",
          confidence: 0.8,
          remove: false,
          metadata: {
            ENS_NAME: notifierName,
          },
        })
      );
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: scammerEoa,
          label: "victim_EOA",
          confidence: 0.8,
          remove: false,
          metadata: {},
        })
      );
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: extraInfo.address,
          label: "scammer_EOA",
          confidence: 0.8,
          remove: false,
          metadata: {},
        })
      );
      break;
    case "EOA":
      description = `${scammerEoa} was flagged as a scam by ${notifierEoa} ${notifierName}`;
      severity = FindingSeverity.High;
      type = FindingType.Suspicious;
      alertId = "SCAM-NOTIFIER-EOA";
      metadata.scammer_eoa = scammerEoa;
      //metadata.scammer_contracts = scammerContracts ? scammerContracts.join(', ') : '';
      metadata.notifier_eoa = notifierEoa;
      metadata.notifier_name = notifierName;
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: notifierEoa,
          label: "notifier_EOA",
          confidence: 0.8,
          remove: false,
          metadata: {
            ENS_NAME: notifierName,
          },
        })
      );
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: scammerEoa,
          label: "scammer_EOA",
          confidence: 0.8,
          remove: false,
          metadata: {},
        })
      );
      break;
    case "CONTRACT":
      description = `${scammerContract} was flagged as a scam by ${notifierEoa} ${notifierName}`;
      severity = FindingSeverity.High;
      type = FindingType.Suspicious;
      alertId = "SCAM-NOTIFIER-CONTRACT";
      metadata.scammer_contract = scammerContract;
      const scammer_eoa = await getContractCreation(
        scammerContract,
        chainId,
        keys
      );
      metadata.scammer_eoa = scammer_eoa || "Error finding deployer";
      metadata.notifier_eoa = notifierEoa;
      metadata.notifier_name = notifierName;
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: scammerEoa,
          label: "notifier_EOA",
          confidence: 0.8,
          remove: false,
          metadata: {
            ENS_NAME: notifierName,
          },
        })
      );
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: scammerEoa,
          label: "scammer_Contract",
          confidence: 0.8,
          remove: false,
        })
      );
      if (scammer_eoa) {
        labels.push(
          Label.fromObject({
            entityType: EntityType.Address,
            entity: scammer_eoa,
            label: "scammer_EOA",
            confidence: 0.8,
            remove: false,
            metadata: {},
          })
        );
      }
      break;
    case "NEW_NOTIFIER":
      description = `New scam notifier identified ${notifierEoa} ${notifierName}`;
      severity = FindingSeverity.Info;
      type = FindingType.Info;
      alertId = "NEW-SCAM-NOTIFIER";
      metadata.similar_notifier_eoa = similarNotifiers?.sharingAddress || "err";
      const similar_notifier_name =
        chainId == 1
          ? await getAddressName(provider, metadata.similar_notifier_eoa)
          : "Not Found";
      metadata.similar_notifier_name = similar_notifier_name || "Not Found";
      metadata.union_flagged = similarNotifiers?.sharedRecipients?.length
        ? similarNotifiers.sharedRecipients.join(", ")
        : "";
      metadata.notifierName = notifierName || "Not found";
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: notifierEoa,
          label: "new_notifier_EOA",
          confidence: 1.0,
          remove: false,
          metadata: {
            ENS_NAME: notifierName,
          },
        })
      );
      labels.push(
        Label.fromObject({
          entityType: EntityType.Address,
          entity: scammerEoa,
          label: "scammer_EOA",
          confidence: 0.8,
          remove: false,
          metadata: {},
        })
      );
      for (const e of similarNotifiers?.sharedRecipients || []) {
        labels.push(
          Label.fromObject({
            entityType: EntityType.Address,
            entity: e,
            label: "union_flagged",
            confidence: 0.8,
            remove: false,
            metadata: {},
          })
        );
      }
      break;
  }

  return Finding.fromObject({
    name: "Scam Notifier Alert",
    description,
    alertId,
    severity,
    type,
    metadata,
    addresses,
    labels,
  });
}
