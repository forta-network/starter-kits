# Disperse / Multisend batched transactions

## Description

Disperse / Multisend are apps used to distribute ERC-20 to multiple addresses in one transaction.
Although they are useful to reduce gas fees by sending transactions in batches, many use them as part of their scam schemes. 

The goal of this bot is to alert when someone is using any of these apps in order to send native tokens or any other ERC-20 token.

The ETH transfers are ignored.

## Supported Chains

- Ethereum
- List any other chains this agent can support e.g. BSC

## Usage

## Alerts

Describe each of the type of alerts fired by this agent

- `BATCHED-ERC20-TX`:
  - Fired when a transaction calls either:
    - `disperseToken`, `disperseTokenSimple` from the [`Disperse` contract][etherscan-contract-disperse]
    - or `multisendToken` from the [`Multisend` contract][etherscan-contract-multisend]
  - Severity is always set to "info"
  - Type is always set to "info"
  - Labels:
    - the origin address of the transaction
  - Metadata:
    - `transactions`: the serialized list of arguments for each transaction, IE a list of `(recipient, value)` tuples
    - `count`: the number of transfers contained in the batch

## Deployment

The code is bundled in a Docker container.

## Tests

### Data

The agent behaviour can be verified with the following transactions:

- ETH transactions:
  - Disperse: [0xa7f0f0470e9be92b10c57273087cef31774c1284acf3d3b56e3e92c504437fb4][etherscan-tx-disperse-eth]
  - Multisend: [0xad2f3e0c98a8951214de9bf0aa1a46684e8f594ceec2e34a81eaa24637cfe771][etherscan-tx-multisend-eth]
- Token transactions:
  - Disperse: [0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c][etherscan-tx-disperse-token]
  - Multisend: [0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5][etherscan-tx-multisend-token]

## Todo

[x] data
[x] custom alerts
[x] metrics
[x] disperse
[x] multisend
[ ] discuss: ignore ETH? / severity level / metadata
[ ] options / CLI flags? (filters: address = token / eth / amount / from, default = all / any)
[ ] limit to 30 alerts / days => less than 1000 / month
[ ] [review](https://github.com/forta-network/bot-review-checklist)
[ ] chain agents
[ ] sharding
[ ] generic

## Metrics

Signatures:

- `Disperse.disperseEther`: `0xe63d38ed`
- `Disperse.disperseToken`: `0xc73a2d60`
- `Disperse.disperseTokenSimple`: `0x51ba162c`
- `Multisend.multisendEther`: `0xab883d28`
- `Multisend.multisendToken`: `0x0b66f3f5`

The web app for Disperse never uses `disperseTokenSimple`: custom calls to this method are more suspect.

[etherscan-contract-disperse]: https://etherscan.io/address/0xd152f549545093347a162dce210e7293f1452150#code
[etherscan-contract-multisend]: https://etherscan.io/address/0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe#code
[etherscan-tx-disperse-eth]: https://etherscan.io/tx/0xa7f0f0470e9be92b10c57273087cef31774c1284acf3d3b56e3e92c504437fb4
[etherscan-tx-disperse-token]: https://etherscan.io/tx/0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c
[etherscan-tx-multisend-eth]: https://etherscan.io/tx/0xad2f3e0c98a8951214de9bf0aa1a46684e8f594ceec2e34a81eaa24637cfe771
[etherscan-tx-multisend-token]: https://etherscan.io/tx/0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5
[phalcon-disperse-token]: https://explorer.phalcon.xyz/tx/eth/0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c
[phalcon-multisend-token]: https://explorer.phalcon.xyz/tx/eth/0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5


```js
const _abi = {name: 'multisendEther', type: 'function', inputs: [{type: 'address[]', name: 'recipients'}, {type: 'uint256[]', name: 'values'}]};
const _args = [['0x33d73cc0e060939476a10e47b86a4568c7dcf261', '0x3d02b87ae906f1d6f130832f67e5c10c9f869205', '0xe1c35a5edff5a5fc92b294289a1ea00a2db1659f'], ['0xb1a2bc2ec5', '0xb1a2bc2ec5', '0xb1a2bc2ec5']];
web3.eth.abi.encodeFunctionCall(_abi, _args);
```
