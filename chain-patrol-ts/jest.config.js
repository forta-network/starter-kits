module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testPathIgnorePatterns: ["dist"],
  moduleNameMapper: {
    axios: 'axios/dist/node/axios.cjs',
}
};
