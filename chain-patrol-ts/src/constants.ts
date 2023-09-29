// `YYYY-MM-DD` Format
export const INIT_API_QUERY_DATE = "2023-08-28";

const ONE_DAY = 60 * 60 * 24;
const ETHEREUM_BLOCK_TIME = 12;
export const ETHEREUM_BLOCKS_IN_ONE_DAY = ONE_DAY / ETHEREUM_BLOCK_TIME;
export const MAX_ASSET_ALERTS_PER_BLOCK: number = 50;
export const MAX_FETCH_ATTEMPTS = 3;

export const ASSET_TYPES = ["URL", "PAGE", "TWITTER"];
export const ASSET_BLOCKED_STATUS = "BLOCKED";

// TODO: Determine the actual URL we will use
// to store the API key
export const DATABASE_URL = "";
export const ASSET_LIST_URL = "https://app.chainpatrol.io/api/v2/asset/list";
export const ASSET_DETAILS_URL = "https://app.chainpatrol.io/api/v2/asset/details";
