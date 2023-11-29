module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testPathIgnorePatterns: ["dist"],
  moduleNameMapper: {
    "node-fetch": "<rootDir>/node_modules/cross-fetch",
  },
};
