module.exports = {
  verbose: true,
  testEnvironment: "node",
  testPathIgnorePatterns: ["dist"],
  moduleNameMapper: {
    "^./controllers/parseBlur(.*)$": "<rootDir>/src/controllers/parseBlur.ts",
    "^./controllers/parseLooksRare(.*)$": "<rootDir>/src/controllers/parseLooksRare.ts",
    "^./controllers/parseNftTrader(.*)$": "<rootDir>/src/controllers/parseNftTrader.ts",
    "^./controllers/parseSeaport(.*)$": "<rootDir>/src/controllers/parseSeaport.ts",
    "^./controllers/parseTransferEvent(.*)$": "<rootDir>/src/controllers/parseTransferEvent.ts",
    "^./controllers/parseTx(.*)$": "<rootDir>/src/controllers/parseTx.ts",
    "^./config/logEventTypes(.*)$": "<rootDir>/src/config/logEventTypes.ts",
    "^./markets(.*)$": "<rootDir>/src/config/markets.ts",
    "^./initialize(.*)$": "<rootDir>/src/config/initialize.ts"
  },  
  transformIgnorePatterns: [
    'node_modules/(?!(@adraffy/ens-normalize)/)',
  ],
  transform: {
    '^.+\\.(js|ts)$': '<rootDir>/jest-transformer.js',
  } 
};
