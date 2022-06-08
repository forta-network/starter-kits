# Chainalysis Sanctioned Addresses

## Description

This bot detects transactions that involve Chainalysis sanctioned addresses.

The bot listens to the [Chainalysis Sanction Oracle Contract](https://go.chainalysis.com/chainalysis-oracle-docs.html)'s sanctioned events and maintains a local list of sanctioned addresses.

## Supported Chains

- Ethereum, BSC, Polygon, Avalanche, Arbitrum, Optimism, Fantom

## Alerts

- CHAINALYSIS-SANCTIONED-ADDR-TX
  - Fired when a transaction or subtransaction involves one of the sanctioned addresses
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata "sanctioned_address" field specifies which sanctioned address was detected
  - Metadata "data_source" field specifies source where the sanctioned address was listed

- CHAINALYSIS-SANCTIONED-ADDR-EVENT
  - Fired when Chainalysis adds a new list of addresses to the sanctioned list.
  - Severity is always set to "medium"
  - Type is always set to "info"
  - Metadata "addresses" field specifies list of new sanctioned addresses
  - Metadata "data_source" field specifies the sanctioned list source

- CHAINALYSIS-UNSANCTIONED-ADDR-EVENT
  - Fired when Chainalysis removes a list of addresses from the sanctioned list.
  - Severity is always set to "low"
  - Type is always set to "info"
  - Metadata "addresses" field specifies list of unsanctioned addresses
  - Metadata "data_source" field specifies the sanctioned list source

## Testing

### Transaction Involving Sanctioned Address

- 0x82a4e7d56fd67e9d9934126bb75bd239a88ef074b1857c00f4bae39077922b7f (involves Chainalysis Sanctioned address = 0xfec8a60023265364d066a1212fde3930f6ae8da7)

```bash
$ npm run tx 0x82a4e7d56fd67e9d9934126bb75bd239a88ef074b1857c00f4bae39077922b7f

1 findings for transaction 0x82a4e7d56fd67e9d9934126bb75bd239a88ef074b1857c00f4bae39077922b7f {
  "name": "Sanctioned Address",
  "description": "Transaction involving a sanctioned address: 0xfec8a60023265364d066a1212fde3930f6ae8da7",
  "alertId": "CHAINALYSIS-SANCTIONED-ADDR-TX",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "sanctioned_address": "0xfec8a60023265364d066a1212fde3930f6ae8da7",
    "data_source": "Chainalysis"
  }
}
```

### Sanction Address List Update Transaction

- 0xc9d7b45c94a5b78e940c98d1f25818788decaa583042f229f97a9cea194d5e18 (Chainalysis Add to Sanctions List Transaction)

```bash
$ npm run tx 0xc9d7b45c94a5b78e940c98d1f25818788decaa583042f229f97a9cea194d5e18

1 findings for transaction 0xc9d7b45c94a5b78e940c98d1f25818788decaa583042f229f97a9cea194d5e18 {
  "name": "Sanctioned Addresses Event",
  "description": "Addresses added to sanctions list",
  "alertId": "CHAINALYSIS-SANCTIONED-ADDR-EVENT",
  "protocol": "ethereum",
  "severity": "Medium",
  "type": "Info",
  "metadata": {
    "addresses": [
      "0xf7b31119c2682c88d88d455dbb9d5932c65cf1be",
      "0x35fb6f6db4fb05e6a4ce86f2c93691425626d4b1",
      "0x3e37627deaa754090fbfbb8bd226c1ce66d255e9",
      "0x08723392ed15743cc38513c4925f5e6be5c17243"
    ],
    "data_source": "Chainalysis"
  }
}
```