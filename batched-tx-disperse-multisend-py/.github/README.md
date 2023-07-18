# Batch Transfers Bot

## Description

Disperse / Multisend are apps used to distribute tokens to multiple addresses in one transaction.
Although they are useful to reduce gas fees by sending transactions in batches, many use them as part of their scam schemes. 

The goal of this bot is to alert when someone is using a similar app in order to send multiple tokens.

## Support

The bot runs on all the chains:

- Ethereum
- BSC
- Polygon
- Optimism
- Arbitrum
- Avalanche
- Fantom

It scans for the following token transfers:

- ERC20
- ERC721
- all native currencies (ETH, MATIC, etc)

It could also be used to detect airdrops (and their associated scam: sleepdrops).
They are very similar, the main difference being that those calls don't require array of addresses (recipients) as inputs.
By default, this option is disabled and the bot scans for batch transactions only.

## Alerts

The bot only emits `info` alerts:

- `BATCHED-ERC20-TX`:
  - Metadata:
    - `transfers`: a list of ERC20 transfer events, with their inputs (IE `token, from, to, value`)
- `BATCHED-ERC721-TX`:
  - Metadata:
    - `transfers`: a list of ERC721 transfer events, with their inputs (IE `token, from, to, value` where value is a token id)
- `BATCHED-ETH-TX` / `BATCHED-MATIC-TX` / `BATCHED-{CURRENCY}-TX`
  - Metadata:
    - `transfers`: a list of balance delta, for the native currency of the target chain

For all the alerts:    

- Type is always set to `info`
- Severity is either `info` or `low` depending on the estimated probability that the transaction is malicious
- Metadata:
  - `confidence`: the estimated probability that the transaction contains batch transfers (see [the section on metrics](#confidence-malicious-score))
  - `malicious`: the estimated probability that the transaction is malicious (see [the section on metrics](#confidence-malicious-score))
  - `chain_id`: the chain id
  - `from`: the transaction sender
  - `to`: the transaction recipient
  - `token`: the type of token, IE ERC20 / ERC721 / NATIVE
  - `count`: the number of transfers wrapped in the transaction
  - `anomaly_score`: the alert rate for this combination of bot / alert type
- Labels:
  - `entity`: address of the sender, if the transaction is assessed as malicious

## Filtering Options

The file [`options.py`](src/options.py) contains filtering options.

All of these criteria must be satisfied by a transaction to be reported:

- `TARGET_CONTRACT` (`str`, length 42)
  - should be either the empty string `''` or an address like `'0x767fe9edc9e0df98e07454847909b5e959d7ca0e'`
  - if empty the agent reports all findings
  - otherwise it will only report transactions sent the given contract address
- `TARGET_TOKEN` (`str`, length 42)
  - should be either the empty string `''` or an address like `'0x767fe9edc9e0df98e07454847909b5e959d7ca0e'` (`0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` for native currencies)
  - if empty the agent reports all findings
  - otherwise it will only report transfers of the given 
- `MIN_TRANSFER_COUNT` (`int`)
  - the minimum number of transfers wrapped in the transaction
- `MIN_TRANSFER_TOTAL_ERC20`:
  - the minimum amount of ERC20 tokens transfered in total
- `MIN_TRANSFER_TOTAL_NATIVE`:
  - the minimum amount of native currency transfered in total
- `MIN_CONFIDENCE_SCORE`:
  - the minimum probabillity that a given transaction is a batch transfer
- `MIN_MALICIOUS_SCORE`:
  - the minimum probability that a given transaction is malicious

## Deployment

The code is bundled in a Docker container.

## Implementation: Metrics & Edge Cases

The bot decisions are guided by probability metrics / scores.

For example, the confidence that a transaction contains a batch of transfers can be interpreted as follows:

- if equal to `0.5`, it is undecided, the bot didn't find enough evidence for / against
- from `0.5` to `1`, the chances go toward the certainty of a batch transaction
- from `0.5` to `0`, the agent is ruling out the possibility of a batch transaction

These metrics are computed in two steps.

### Indicators

First, the bot parses the transaction metadata and looks for relevant patterns:

- on the method selector:
  - the batching methods have predictable names and arguments
  - a wordlist of all the probable signature is generated
  - then the actual selector of the transaction call is compared with the wordlist
- on the input data:
  - arrays have a specific format, they can be detected without the contract ABI
  - the bot looks for arrays of addresses (the recipients) and arrays of values (the amounts to transfer)
- on the events:
  - ERC20 and ERC721 standards are supposed to emit `Transfer` events when the tokens are moved
  - the bot parses the transaction log, looking for those events
- on the balances:
  - the balances of all the addresses involved can be checked
  - in particular, the balance of the `from` address is expected to change (decrease) while the `to` is supposed to remain mostly unchanged (apart from the possible collection of a fee)

### Combination

Then, the transaction is scored differently depending on the presence / absence of each of these indicators.

The indicators are turned into quantified probabilities with the conflation function, $\xi$:

$$\begin{align}
Conflation(p_1, ..., p_N) &= \xi(p_1, ..., p_N) \\
                          &= \frac{\prod_{i=1}^{N} p_i}{\prod_{i=1}^{N} p_i + \prod_{i=1}^{N} (1 - p_i)}
\end{align}$$

Given a list of probabilities $\{p_i\}$ and a extra probability $p$, the conflation has the following properties:

- if $p = 0.5$ then $\xi(p_1, ..., p_N, p) = \xi(p_1, ..., p_N)$
- if $p > 0.5$ then $\xi(p_1, ..., p_N, p) > \xi(p_1, ..., p_N)$
- if $p < 0.5$ then $\xi(p_1, ..., p_N, p) < \xi(p_1, ..., p_N)$

For example:

- when an indicator (presence / absence) doesn't add information it can be scored as `0.5`.
- when it greatly increases the probability `0.9`
- when it slightly decreases the probability `0.4`
- when it strongly decreases the probability `0.1`
- etc

Rather than each individual score, it is the tendency of the list of scores that drives the overall metric toward a low / high probability.

#### Confidence & Malicious scores

There are two types of scores computed:

- `confidence` score: estimated probability that a transaction is correctly classified
- `malicious` score: estimated probability that a transaction has evil intents

The `malicious` score comes into play once the bot has identified a batch transaction.
For now, this score will be higher than `0.5` in 2 cases:

- if the `to` contract accumulates wealth (native or ERC tokens):
  - a batching contract is supposed to redistribute the tokens it receives
  - so if its balance has significantly increased after the transaction, this behavior is tagged as malicious
  - there is a tolerance for the fees it may gather
- if the `to` contract performs transfers of `0` amount:
  - this technique is often used in phishing scams

### Edge Cases

When only a subset of the indicators are satisfied, the transaction may actually be of a connex type:

- no array of addresses in the input:
  - the contract may be performing an airdrop (sending to random addresses)
  - in turn these airdrops can be malicious: non standard tokens, fake copy of a valid token etc
- no array of amounts in the input:
  - the transaction may be a phishing attack, sending random or 0 amount of tokens
- low transfer count:
  - the transaction may be a token swap
  - typically around 4-6 transfers for a (Uni)swap
  - sometimes a little more (8-10) for MEV bots
- low transfer total amount:
  - most likely a phishing attempt, since they often transfer `0` amounts of tokens
- no event / token:
  - the transaction may be a transfer of native currency

## Tests

The bot comes with extensive unit tests that can be run with `python -m pytest` from the root directory of this bot.

### Data

The test data is made of serialized live transaction events, using `pickle`.
It is located in `tests/.data/` and classified by transaction type.

Otherwise, the agent behaviour can be verified on the following transactions:

- ETH transactions:
  - Disperse: [0xa7f0f0470e9be92b10c57273087cef31774c1284acf3d3b56e3e92c504437fb4][etherscan-tx-disperse-eth]
  - Multisend: [0xad2f3e0c98a8951214de9bf0aa1a46684e8f594ceec2e34a81eaa24637cfe771][etherscan-tx-multisend-eth]
- Token transactions:
  - Disperse: [0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c][etherscan-tx-disperse-token]
  - Multisend: [0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5][etherscan-tx-multisend-token]

## Performance

The web requests are cached, in particular balance checks require time and are performed only when relevant.

## TODOs & Thoughts

The bot could be improved by:

- adding other standards, like ERC1155
- sorting / splitting the selector wordlist to classify the methods by their signature 
- extending the wordlists with:
  - new patterns
  - additional keywords
  - signatures for batch `transferFrom` functions

Other potential avenues for improvements:

- split the repository in standalone python modules:
  - the parsing logic for the selectors and arrays could be reused
  - the various indicators are related to other types of transactions / scams
- the metric & decision process could be formalized for the network:
  - having quantified metrics helps with the interpretation / debugging
  - it explicitely breaks down a given decision along several axes, while if-then-else are hidden
  - finally it could be a basis to build / extend ML datasets

## Author

[apehex](https://github.com/apehex)

[etherscan-contract-disperse]: https://etherscan.io/address/0xd152f549545093347a162dce210e7293f1452150#code
[etherscan-contract-multisend]: https://etherscan.io/address/0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe#code
[etherscan-tx-disperse-eth]: https://etherscan.io/tx/0xa7f0f0470e9be92b10c57273087cef31774c1284acf3d3b56e3e92c504437fb4
[etherscan-tx-disperse-token]: https://etherscan.io/tx/0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c
[etherscan-tx-multisend-eth]: https://etherscan.io/tx/0xad2f3e0c98a8951214de9bf0aa1a46684e8f594ceec2e34a81eaa24637cfe771
[etherscan-tx-multisend-token]: https://etherscan.io/tx/0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5
[phalcon-disperse-token]: https://explorer.phalcon.xyz/tx/eth/0x2e311b6e9c842e4ec06712cad2acb6be9d6eec341c348a7dc3aac51ec9a8426c
[phalcon-multisend-token]: https://explorer.phalcon.xyz/tx/eth/0x78b093c64e09cb7a3ce6bad2480549b058550faa5ba21be7c19ad732dc761fc5
