import { Network } from "forta-agent";

export const STABLECOINS = [
  "USDT",
  "USDC",
  "DAI",
  "TUSD",
  "BUSD",
  "USDT.e",
  "USDt",
  "USDC.e",
  "BUSD.e",
  "DAI.e",
];

export const FLOOR_PRICE_CURRENCIES: Record<
  string,
  { network: Network; tokenAddress: string }
> = {
  GALA: {
    network: Network.MAINNET,
    tokenAddress: "0xd1d2eb1b1e90b638588728b4130137d262c87cae",
  },
};

export const FILTERED_OUT_NFTS = [
  "0xe3b1d32e43ce8d658368e2cbff95d57ef39be8a6", // SPACE ID - .bnb (BNB Chain)
];
