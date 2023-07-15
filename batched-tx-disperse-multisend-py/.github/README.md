# Disperse / Multisend batched transactions

## Description

Disperse / Multisend are apps used to distribute tokens to multiple addresses in one transaction.
Although they are useful to reduce gas fees by sending transactions in batches, many use them as part of their scam schemes. 

The goal of this bot is to alert when someone is using any of these apps in order to send native tokens or any other ERC-20 token.

## Supported Chains

The bot is specific to the contracts [`Disperse`][etherscan-contract-disperse] and [`Multisend`][etherscan-contract-multisend].

So it runs on a single chain:

- Ethereum

## Filtering & Edge Cases

- using batching to perform a single transfer
- no input => airdrop
- no token => native

## Alerts

The bot only emits `info` alerts:

- `BATCHED-ERC20-TX`:
  - Fired when a transaction calls either:
    - `disperseToken`, `disperseTokenSimple` from the [`Disperse` contract][etherscan-contract-disperse]
    - or `multisendToken` from the [`Multisend` contract][etherscan-contract-multisend]
  - Severity is "low" in case of a manual call, otherwise it is set to "info" (call via the web app)
  - Type is always set to "info"
  - Labels:
    - the origin address of the transaction
  - Metadata:
    - `transactions`: the serialized list of arguments for each transaction, IE a list of `(recipient, value)` tuples
    - `count`: the number of transfers contained in the batch
- `BATCHED-ETH-TX`:
  - Fired when a transaction calls either:
    - `disperseEther` from the [`Disperse` contract][etherscan-contract-disperse]
    - or `multisendEther` from the [`Multisend` contract][etherscan-contract-multisend]
  - Severity is always set to "info"
  - Type is always set to "info"
  - Labels:
    - the origin address of the transaction
  - Metadata:
    - `transactions`: the serialized list of arguments for each transaction, IE a list of `(recipient, value)` tuples
    - `count`: the number of transfers contained in the batch

## Configuration

The file [`constants.py`](src/constants.py) contains filtering options.

- `TOKEN`:
  - should be either the empty string `''` or an address like `'0x767fe9edc9e0df98e07454847909b5e959d7ca0e'`
  - if empty the agent reports all findings
  - otherwise it will only report transfers batched for a specific ERC20 token

## Deployment

The code is bundled in a Docker container.

## Tests

The test can be run with `python -m pytest`.

### Data

The agent behaviour can be verified on the following transactions:

- ETH transactions:
  - Disperse: [0xa7f0f0470e9be92b10c57273087cef31774c1284acf3d3b56e3e92c504437fb4][etherscan-tx-disperse-eth]
  - Multisend: [0xad2f3e0c98a8951214de9bf0aa1a46684e8f594ceec2e34a81eaa24637cfe771][etherscan-tx-multisend-eth]
- Token transactions:
  - Disperse: [0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c][etherscan-tx-disperse-token]
  - Multisend: [0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5][etherscan-tx-multisend-token]

## Metrics

### Indicators

### Combination

Uses the conflation to combine the scores from each source.

#### Confidence

#### Malicious Behaviours

The bot looks for transactions to the following contract:

- Ethereum:
  - Disperse: [`0xd152f549545093347a162dce210e7293f1452150`][etherscan-contract-disperse]
  - Multisend: [`0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe`][etherscan-contract-multisend]

And checks whether specific functions are called by their signature:

- `Disperse.disperseEther`: `0xe63d38ed`
- `Disperse.disperseToken`: `0xc73a2d60`
- `Disperse.disperseTokenSimple`: `0x51ba162c`
- `Multisend.multisendEther`: `0xab883d28`
- `Multisend.multisendToken`: `0x0b66f3f5`

The web app for Disperse never uses `disperseTokenSimple`: custom calls to this method are more suspect.

## Performance

The web requests are cached, in particular balance checks.

## TODOs

- add other standards, like ERC1155
- extend the wordlists with:
  - new patterns
  - additional keywords
  - signatures for batch `transferFrom` functions 

[etherscan-contract-disperse]: https://etherscan.io/address/0xd152f549545093347a162dce210e7293f1452150#code
[etherscan-contract-multisend]: https://etherscan.io/address/0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe#code
[etherscan-tx-disperse-eth]: https://etherscan.io/tx/0xa7f0f0470e9be92b10c57273087cef31774c1284acf3d3b56e3e92c504437fb4
[etherscan-tx-disperse-token]: https://etherscan.io/tx/0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c
[etherscan-tx-multisend-eth]: https://etherscan.io/tx/0xad2f3e0c98a8951214de9bf0aa1a46684e8f594ceec2e34a81eaa24637cfe771
[etherscan-tx-multisend-token]: https://etherscan.io/tx/0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5
[phalcon-disperse-token]: https://explorer.phalcon.xyz/tx/eth/0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c
[phalcon-multisend-token]: https://explorer.phalcon.xyz/tx/eth/0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5
