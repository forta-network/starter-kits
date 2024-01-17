import {
  Finding,
  FindingSeverity,
  FindingType,
  Label,
  EntityType,
} from "forta-agent";
import { TransactionRecord } from "src/types/types";

export function createCustomAlert(
  record: TransactionRecord,
  description: string,
  alert_name: string,
  findingType: FindingType,
  severity: FindingSeverity,
  chainId: number,
  additionalMetadata: { [key: string]: string } = {}
): Finding {
  const metadata: { [key: string]: string } = {
    interactedMarket: record.interactedMarket,
    transactionHash: record.transactionHash,
    toAddr: record.toAddr!,
    fromAddr: record.fromAddr!,
    initiator: record.initiator!,
    totalPrice: record.totalPrice.toString(),
    avgItemPrice: record.avgItemPrice.toString(),
    contractAddress: record.contractAddress,
    floorPrice: record.floorPrice.toString(),
    currency: record.currency,
    timestamp: record.timestamp.toString(),
    floorPriceDiff: record.floorPriceDiff || "ERROR",
    ...additionalMetadata,
  };

  const labels: Label[] = [];

  let protocol_name = "ethereum";
  if (chainId === 56) protocol_name = "bsc";
  if (chainId === 137) protocol_name = "polygon";

  let market;
  switch (metadata.interactedMarket) {
    case "blur" || "blurswap":
      market = "Blur 🟠";
      break;
    case "opensea":
      market = "Opensea 🌊";
      break;
    case "looksrare":
      market = "LooksRare 👀💎";
      break;
    default:
      break;
  }

  const findingInput = {
    name: "scammer-nft-trader",
    description: market ? `[${market}] ${description}` : description,
    alertId: alert_name,
    severity: severity,
    type: findingType,
    metadata,
    labels,
    protocol: protocol_name,
  };

  let alertLabel: Label[] = [];

  if (alert_name == "nft-sale") {
    alertLabel.push({
      entityType: EntityType.Address,
      entity: `${additionalMetadata.tokenKey},${record.contractAddress}`,
      label: "nft-sale-record",
      confidence: 0.9,
      remove: false,
      metadata: {},
    });
    alertLabel.push({
      entityType: EntityType.Address,
      entity: `${record.fromAddr}`,
      label: "nft-sender",
      confidence: 0.8,
      remove: false,
      metadata: {},
    });
    alertLabel.push({
      entityType: EntityType.Address,
      entity: `${record.toAddr}`,
      label: "nft-receiver",
      confidence: 0.8,
      remove: false,
      metadata: {},
    });
  } else if (alert_name == "nft-sold-above-floor-price") {
    alertLabel.push({
      entityType: EntityType.Address,
      entity: `${additionalMetadata.tokenKey},${record.contractAddress}`,
      label: "nft-sold-above-floor-price",
      confidence: 0.9,
      remove: false,
      metadata: {},
    });
  } else if (alert_name == "nft-phishing-sale") {
    alertLabel.push({
      entityType: EntityType.Address,
      entity: `${additionalMetadata.tokenKey},${record.contractAddress}`,
      label: "nft-phising-transfer",
      confidence: 0.9,
      remove: false,
      metadata: {},
    });

    alertLabel.push({
      entityType: EntityType.Address,
      entity: `${record.fromAddr}`,
      label: "nft-phishing-victim",
      confidence: 0.8,
      remove: false,
      metadata: {},
    });

    alertLabel.push({
      entityType: EntityType.Address,
      entity: `${record.toAddr}`,
      label: "nft-phishing-attacker",
      confidence: 0.8,
      remove: false,
      metadata: {},
    });
  }

  let find: Finding = Finding.from(findingInput);

  for (const label of alertLabel) {
    find.labels.push(label);
  }

  find.addresses.push(record.fromAddr!);
  find.addresses.push(record.toAddr!);
  find.addresses.push(record.initiator!);

  //console.log('findingInput', findingInput);
  return find;
}
