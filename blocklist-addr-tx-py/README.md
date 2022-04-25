# Blocklisted Address Bot

## Description

This bot detects transactions that involve blocklisted addresses.

Blocklist source:

* Blocklisted addresses in [USDC Token Contract](https://etherscan.io/address/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48)
* Blocklisted addresses in [USDT Token Contract](https://etherscan.io/address/0xdac17f958d2ee523a2206206994597c13d831ec7)
* Sanctioned addresses by [Chainalysis Sanction Oracle](https://etherscan.io/address/0x40c57923924b5c5c5455c48d93317139addac8fb)
* Addresses labeled as `exploit`, `heist`, and `phish/hack` from [Etherscan](https://etherscan.io/labelcloud)

## Supported Chains

- Ethereum, BSC, Polygon, Avalanche, Arbitrum, Optimism

## Alerts

- FORTA-BLOCKLIST-ADDR-TX
  - Fired when a transaction or subtransaction involves one of the blocklisted addresses
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata "blocklisted_address" field specifies which blocklisted address was detected
  - Metadata "wallet_tag" field displays the blocklisted address's wallet tag.
  - Metadata "data_source" field specifies source of the blocklist where the blocklisted address was listed

## Test Data

### Transactions by blocklisted addresses

- 0xe0bf600d62e99f2f7b0bd6ce27a7167b8c04bd5a06727155c0334ca5c39dfd6c (involves BadgerDAO Exploiter = 0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107)

```bash
$ npm run tx 0xe0bf600d62e99f2f7b0bd6ce27a7167b8c04bd5a06727155c0334ca5c39dfd6c

1 findings for transaction 0xe0bf600d62e99f2f7b0bd6ce27a7167b8c04bd5a06727155c0334ca5c39dfd6c {
  "name": "Blocklisted Address",
  "description": "Transaction involving a blocklisted address: 0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107 with wallet tag: BadgerDAO Exploiter",
  "alertId": "FORTA-BLOCKLIST-ADDR-TX",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "blocklisted_address": "0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107",
    "wallet_tag": "BadgerDAO Exploiter",
    "data_source": "etherscan-exploit-list"
  }
}
```

- 0xf1057c81d9ec661437485a0e224fc94e22e2cfc6717c2d79471bfb8ba25cf443 (involves USDC Banned address = 0x6aCDFBA02D390b97Ac2b2d42A63E85293BCc160e)

```bash
$ npm run tx 0xf1057c81d9ec661437485a0e224fc94e22e2cfc6717c2d79471bfb8ba25cf443

1 findings for transaction 0xf1057c81d9ec661437485a0e224fc94e22e2cfc6717c2d79471bfb8ba25cf443 {
  "name": "Blocklisted Address",
  "description": "Transaction involving a blocklisted address: 0x6acdfba02d390b97ac2b2d42a63e85293bcc160e",
  "alertId": "FORTA-BLOCKLIST-ADDR-TX",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "blocklisted_address": "0x6acdfba02d390b97ac2b2d42a63e85293bcc160e",
    "wallet_tag": "",
    "data_source": "USDC-blocklist"
  }
}
```

- 0xbaf6af6b0ec77113fe516ff7b9703dddc5bd6ebedf9f0556752ba34a3ec2ae47 (involves USDT Banned address = 0x37c545dae781c5ee433e81cdbe54401effd111b4)

```bash
$ npm run tx 0xbaf6af6b0ec77113fe516ff7b9703dddc5bd6ebedf9f0556752ba34a3ec2ae47

1 findings for transaction 0xbaf6af6b0ec77113fe516ff7b9703dddc5bd6ebedf9f0556752ba34a3ec2ae47 {
  "name": "Blocklisted Address",
  "description": "Transaction involving a blocklisted address: 0x37c545dae781c5ee433e81cdbe54401effd111b4",
  "alertId": "FORTA-BLOCKLIST-ADDR-TX",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "blocklisted_address": "0x37c545dae781c5ee433e81cdbe54401effd111b4",
    "wallet_tag": "",
    "data_source": "USDT-blocklist"
  }
}
```

- 0x82a4e7d56fd67e9d9934126bb75bd239a88ef074b1857c00f4bae39077922b7f (involves Chainalysis Sanctioned address = 0xfec8a60023265364d066a1212fde3930f6ae8da7)

```bash
$ npm run tx 0x82a4e7d56fd67e9d9934126bb75bd239a88ef074b1857c00f4bae39077922b7f

1 findings for transaction 0x82a4e7d56fd67e9d9934126bb75bd239a88ef074b1857c00f4bae39077922b7f {
  "name": "Blocklisted Address",
  "description": "Transaction involving a blocklisted address: 0xfec8a60023265364d066a1212fde3930f6ae8da7",
  "alertId": "FORTA-BLOCKLIST-ADDR-TX",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "blocklisted_address": "0xfec8a60023265364d066a1212fde3930f6ae8da7",
    "wallet_tag": "",
    "data_source": "Chainalysis-blocklist"
  }
}
```

### Transactions with blocklisted events

- 0x1736bde1fde86ffa7ee124f4c40aa7d9e1c90c836e4afb5a9df476ba5bd35797 (USDT Blocklisted event)

```bash
$ npm run tx 0x1736bde1fde86ffa7ee124f4c40aa7d9e1c90c836e4afb5a9df476ba5bd35797

updating blocklist: ./usdt_blocklist.txt
0 findings for transaction 0x1736bde1fde86ffa7ee124f4c40aa7d9e1c90c836e4afb5a9df476ba5bd35797
```

- 0x8a28fa4fc1e2efac90490f4358ec223dc0120fe2a36a4c61387c6ccb32931da3 (USDC Blocklisted event)

```bash
$ npm run tx 0x8a28fa4fc1e2efac90490f4358ec223dc0120fe2a36a4c61387c6ccb32931da3

updating blocklist: ./usdc_blocklist.txt
0 findings for transaction 0x8a28fa4fc1e2efac90490f4358ec223dc0120fe2a36a4c61387c6ccb32931da3
```

- 0x1d3d64b26cfdaeb328d01d09b407f3a806d3254109e4476461b3960592eae902 (Chainalysis Sanctioned event)

```bash
$ npm run tx 0x1d3d64b26cfdaeb328d01d09b407f3a806d3254109e4476461b3960592eae902

updating blocklist: ./chainalysis_blocklist.txt
0 findings for transaction 0x1d3d64b26cfdaeb328d01d09b407f3a806d3254109e4476461b3960592eae902
```
