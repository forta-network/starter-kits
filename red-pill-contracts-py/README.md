# Detecting Red-Pill Contracts

## Description

Implementation for the detection techniques described in the [report about smart contract evasion techniques][report-web3-evasion] by the [Forta TRi][forta-threat-research-initiative].

Here, "evasion" refers to any tactic that deceives end-users or circumvents defense mechanisms.

More specifically, the bot is focused on contrats that try to detect / evade simulation environments.
As in the movie "Matrix" they are aware that they live in a simulation, hence the name "red-pill".

## Support

The bots use the transaction traces, so they only runs on Ethereum for now.

## Table of Contents

- [Example](#example)
- [Alerts](#alerts)
- [Detection Process](#detection-process)
- [Options](#options)
- [Implementations](#implementations)
- [Development](#development)
  - [Changelog](#changelog)
  - [Todo](#todo)
  - [Performances](#performances)
- [Credits](#credits)
- [License](#license)

## Example

Boiled to the essential, a red-pill contract looks like:

```solidity
contract RedPill {
    function print() public view returns (string memory) {
        if (block.coinbase == address(0x0000000000000000000000000000000000000000)) {
            return "blue pill";
        } else {
            return "red pill";
        }
    }
}
```

## Alerts

The red-pill contracts are spotted when created to perform static analysis on the bytecode:

- `LOGIC-BOMB-RED-PILL-DEPLOYMENT`:
    - the address of the contract is attached as a label

For all the alerts:    

- Type is always set to `Suspicious`
- Severity is always `Info`
- Metadata:
  - `confidence`: the estimated probability of a given detection
  - `chain_id`: the chain id
  - `from`: the transaction sender
  - `to`: the transaction recipient
  - `anomaly_score`: the alert rate for this combination of bot / alert type

## Detection Process

Red-pill contracts try to detect simulation environments by looking for default values in the global variables.

The detection looks for conditional branches depending on the global variables.
These tests have a pattern that can be directly found in the bytecode with regex.

It matches chunks of HEX encoded bytecode like:

```
600073ffffffffffffffffffffffffffffffffffffffff164173ffffffffffffffffffffffffffffffffffffffff16141561012757
```

```
6000                                          # PUSH1 0
73ffffffffffffffffffffffffffffffffffffffff16  # cast to address
41                                            # block.coinbase
73ffffffffffffffffffffffffffffffffffffffff16  # cast to address
1415                                          # equality test
610127                                        # PUSH2 => instruction offset
57                                            # JUMPI
```

The detection regex accounts for variation in the compilation process due to solidity version and optimization parameters.

For more details, see [the report][report-web3-evasion].

### Indicators

- bytecode contains a comparison between `COINBASE` and `address(0x0000000000000000000000000000000000000000)`
- bytecode contains a comparison between `PREVRANDAO` and `0`

Note: depending on the EVM version the opcode `0x44` is called `DIFFICULTY` or `PREVRANDAO`.

## Scoring The Transactions

The bot decisions are guided by probability metrics / scores.

### Interpretation Of Probabilities

The confidence that a transaction match a given target is a ratio that can be interpreted as follows:

- if equal to `0.5`, it is undecided, the bot didn't find enough evidence for / against
- from `0.5` to `1`, the chances go toward the certainty of a match
- from `0.5` to `0`, the agent is ruling out the possibility of a match

### Scoring Process

These metrics are computed in two steps:

- first all the indicators (IOCs) are computed
- then each indicator is quantified
- then these individual indicators are combined into a probability

The indicators for each evasion technique are listed in the previous sections.

### Quantifying The Indicators

The indicators are boolean values that signal the presence / absence of a given feature in the transaction.
`True` and `False` values are quantified by their impact on the score:

- `0.5` when the indicator has no impact
- `0.5` to `1` the more it increases the probability of a match
- `0.5` to `0` the more it lessens the probability of a match

### Combining Probabilities

Finally, the list of quantified indicators is turned into probabilities with the conflation function, $\xi$:

$$\begin{align}
Conflation(p_1, ..., p_N) &= \xi(p_1, ..., p_N) \\
                          &= \frac{{\prod_{i=1}}^{N} p_i}{{\prod_{i=1}}^{N} p_i + {\prod_{i=1}}^{N} (1 - p_i)}
\end{align}$$

Given a list of probabilities $\{p_i\}$ and a extra probability $p$, the conflation has the following properties:

- if $p = 0.5$ then $\xi(p_1, ..., p_N, p) = \xi(p_1, ..., p_N)$
- if $p > 0.5$ then $\xi(p_1, ..., p_N, p) > \xi(p_1, ..., p_N)$
- if $p < 0.5$ then $\xi(p_1, ..., p_N, p) < \xi(p_1, ..., p_N)$

For example:

- when an indicator (presence / absence) doesn't add information it can be scored as `0.5`.
- `0.9` to greatly increase the probability
- `0.4` to slightly decrease the probability
- `0.1` to strongly decrease the probability
- etc

Rather than each individual score, it is the tendency of the list of scores that drives the overall metric toward a low / high probability.

## Options

The bot settings are located in `src/options.py`:

```python
MIN_CONFIDENCE = 0.7 # probability threshold
ALERT_HISTORY_SIZE = 16384 # in number of transactions recorded
```

The bot only fires alerts when the probability score for a given threat is above `MIN_CONFIDENCE`.

It keeps a local history of all the alerts raised to compute stats.
The history size is set by `ALERT_HISTORY_SIZE`.

## Implementations

All the detection processes are [detailed in the report][report-web3-evasion].

## Tests

The bots use the libraries [`forta-toolkit`][github-apehex-toolkit] and [`ioseeth`][github-apehex-ioseeth], which come with extensive unit tests.

They can be run in the root directory of each of these packages with `python -m pytest`.

## Development

Contributions welcome!

### Changelog

See [CHANGELOG](.github/CHANGELOG.md).

### TODO

See [TODO](.github/TODO.md).

### Performances

## Credits

Original work by [apehex](https://github.com/apehex).

Relies on the packages:

- [`ioseeth`][github-apehex-ioseeth] for the detection logic
- [`forta-toolkit`][github-apehex-toolkit] for the data wrangling

## License

See [LICENSE.md](LICENSE.md).

[forta-threat-research-initiative]: https://forta.org/blog/investing-in-applied-academic-threat-research/
[github-apehex-ioseeth]: https://github.com/apehex/web3-threat-indicators
[github-apehex-toolkit]: https://github.com/apehex/forta-toolkit
[report-web3-evasion]: https://github.com/apehex/web3-evasion-techniques/blob/main/report/web3-evasion-techniques.pdf
