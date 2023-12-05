const ONE_DAY = 60 * 60 * 24;
export const THIRTY_DAYS_IN_MS = ONE_DAY * 30 * 1000;
const ETHEREUM_BLOCK_TIME = 12;
export const ETHEREUM_BLOCKS_IN_ONE_DAY = ONE_DAY / ETHEREUM_BLOCK_TIME;

export const MAX_ASSET_ALERTS_PER_BLOCK: number = 50;
export const MAX_FETCH_ATTEMPTS = 4;

export const ASSET_TYPES = ["URL", "PAGE", "TWITTER"];

export const DATABASE_URL = "https://research.forta.network/database/owner/secrets.json";
export const ASSET_LIST_URL = "https://app.chainpatrol.io/api/v2/asset/list";
export const ASSET_DETAILS_URL = "https://app.chainpatrol.io/api/v2/asset/details";
