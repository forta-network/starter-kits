"""Evaluate the probability that multiple transfers were bundled in a transaction."""

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src.metrics._indicators as indicators
import src.metrics._probabilities as probabilities

# CONFIDENCE ##################################################################

def confidence_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the probability that multiple transfers were bundled in a transaction."""
    _scores = []
    _data = str(getattr(log.transaction, 'data', '')).lower()
    _block = int(log.block.number)
    # method selector
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_batching_selector(_data),
        true_score=0.9, # almost certainty
        false_score=0.5)) # not all selectors are in the wordlist: neutral
    # list of recipients
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_array_of_addresses(_data),
        true_score=0.7, # the list of recipients is necessary for batching, and not seen in many other types of transactions
        false_score=0.1)) # without a list of recipients, there is almost no chance the contract performs batching
    # list of amounts to transfer
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_array_of_values(_data),
        true_score=0.6, # low prob: the array of values could have another meaning
        false_score=0.4)) # batching can happpen without a list of values: NFT transfers or same amount for all
    # erc20 events OR erc721 events OR balance updates
    _has_token_transfers = (
        indicators.log_has_multiple_erc20_transfer_events(log=log, floor=4)
        or indicators.log_has_multiple_erc721_transfer_events(log=log, floor=4)
        or indicators.multiple_native_token_balances_have_been_updated(w3=w3, data=_data, block=_block, floor=4))
    _scores.append(probabilities.indicator_to_probability(
        indicator=_has_token_transfers,
        true_score=0.8, # a list of transfers almost certainly means batching
        false_score=0.2)) # it's possible the transfered token doesn't follow ERC20 and did not emit an event
    return probabilities.conflation(_scores)

# ANOMALY #####################################################################

# events differ from input data

def malicious_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate."""
    _scores = []
    return probabilities.conflation(_scores)
