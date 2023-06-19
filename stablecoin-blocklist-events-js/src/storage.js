const { fetchJwt } = require("forta-agent");
const { readFileSync } = require("fs");
const fetch = require("node-fetch");

const owner_db = "https://research.forta.network/database/owner/";

const testMode =
  process.env.NODE_ENV && process.env.NODE_ENV.includes("production") ? "main" : "test";

async function _token() {
  const tk = await fetchJwt();
  return { Authorization: `Bearer ${tk}` };
}

async function _loadJson(key) {
  if (testMode === "test") {
    // Loading JSON from local file secrets.json
    const json = readFileSync("secrets.json");
    return JSON.parse(json);
  } else {
    return await fetch(`${owner_db}${key}`, { headers: _token() })
      .then(response => {
        if (response.ok) {
          return response.json();
        } else {
          throw new Error(
            `Error loading JSON from owner db: ${response.status}, ${response.statusText}`
          );
        }
      })
      .catch(error => {
        throw new Error(`Error loading JSON from owner db: ${error.message}`);
      });
  }
}

async function getSecrets() {
  return await _loadJson("secrets.json");
}

module.exports = { getSecrets };
