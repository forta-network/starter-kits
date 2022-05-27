# Blocklisted Address Bot

## Description

This bot detects transactions that involve blocklisted addresses. The blocklist is generated and updated from 4 data sources listed below.

Blocklist source:

* Sanctioned addresses by [Chainalysis Sanction Oracle Contract](https://go.chainalysis.com/chainalysis-oracle-docs.html)
* [Luabase's](https://luabase.com/) `tags` table which includes addresses and wallet tags labeled as `exploit`, `heist`, and `phish/hack` from [Etherscan](https://etherscan.io/labelcloud).

For the first three data sources, the bot listens to each smart contract's blocklisted events and maintains a local list of blocklisted addresses.
For the blocklisted addresses from Luabase, the bot queries their `tags` table with the following SQL statement every 1 minute and maintains a local csv of addresses.

```sql
SELECT DISTINCT address as banned_address, tag as wallet_tag, concat('etherscan-', label, '-list') as data_source
FROM tags WHERE label in ('heist', 'exploit', 'phish-hack')
```

## Supported Chains

- Ethereum, BSC, Polygon, Avalanche, Arbitrum, Optimism, Fantom

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

- 0x1d3d64b26cfdaeb328d01d09b407f3a806d3254109e4476461b3960592eae902 (Chainalysis Sanctioned event)

```bash
$ npm run tx 0x1d3d64b26cfdaeb328d01d09b407f3a806d3254109e4476461b3960592eae902

updating blocklist: ./chainalysis_blocklist.txt
0 findings for transaction 0x1d3d64b26cfdaeb328d01d09b407f3a806d3254109e4476461b3960592eae902
```
w