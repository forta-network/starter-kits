export const BOTS_TO_MONITOR = [
  "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", // funding tornado cash
  "0x2d3bb89e9cecc0024d8ae1a9c93ca42664472cb074cc200fa2c0f77f2be34bf3", // funding fixed float
  "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1", // attack detector
  "0x90596fcef715e22cc073fdc7018039e7af742276dda1baed03032411480c65fd", // suspicious funding
];

export const DAYS_TO_LOOK_BACK = 3;

// Around $11500 at the time of the update
export const VALUE_THRESHOLDS: Record<number, number> = {
  1: 5,
  10: 5,
  56: 22,
  137: 30000,
  250: 24000,
  42161: 5,
  43114: 485,
};

export const alertOriginMap = {
  "TORNADO-CASH": "Tornado Cash",
  "FIXED-FLOAT": "Fixed Float",
  "ATTACK-DETECTOR": "Attack Detector",
};

const ONE_DAY = 60 * 60 * 24;
const THREE_SECOND_BLOCK_TIME = 3;
const ETH_BLOCK_TIME = 12;
export const ETH_BLOCKS_IN_ONE_DAY = ONE_DAY / ETH_BLOCK_TIME;
// Amount of blocks in a day for faster chains
// Using 3 second block times as the average
export const THREE_SECOND_BLOCKS_IN_ONE_DAY = ONE_DAY / THREE_SECOND_BLOCK_TIME;

export const TRUE_POSITIVE_LIST_PATH = "../tp_list.csv";
// Using the Early Attack Detector True Positive list as source of truth
export const TRUE_POSITIVE_LIST_URL =
  "https://raw.githubusercontent.com/forta-network/starter-kits/main/early-attack-detector-py/tp_list.csv";
