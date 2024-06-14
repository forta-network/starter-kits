export const BOTS_TO_MONITOR = [
  "0xa91a31df513afff32b9d85a2c2b7e786fdd681b3cdd8d93d6074943ba31ae400", // funding tornado cash
  "0x2d3bb89e9cecc0024d8ae1a9c93ca42664472cb074cc200fa2c0f77f2be34bf3", // funding fixed float
  "0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1", // attack detector
  "0x90596fcef715e22cc073fdc7018039e7af742276dda1baed03032411480c65fd", // suspicious funding
];

export const DAYS_TO_LOOK_BACK = 3;

// Around $5000 at the time of the update
export const VALUE_THRESHOLDS: Record<number, number> = {
  1: 1.4,
  10: 1.4,
  56: 9,
  137: 8300,
  250: 8000,
  42161: 1.4,
  43114: 160,
};

export const alertOriginMap = {
  "TORNADO-CASH": "Tornado Cash",
  "FIXED-FLOAT": "Fixed Float",
  "ATTACK-DETECTOR": "Attack Detector",
};
