"""Evaluate the probability that multiple transfers were bundled in a transaction."""

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src.metrics._indicators as indicators
import src.metrics._probabilities as probabilities
import src.options as options

# CONFIDENCE ##################################################################

def confidence_score(
    log: TransactionEvent,
    w3: Web3,
    min_transfer_count: int=options.MIN_TRANSFER_COUNT,
    min_transfer_total_erc20: int=options.MIN_TRANSFER_TOTAL_ERC20,
    min_transfer_total_native: int=options.MIN_TRANSFER_TOTAL_NATIVE,
    max_batching_fee: int=options.MAX_BATCHING_FEE[1]
) -> float:
    """Evaluate the probability that multiple transfers were bundled in a transaction."""
    _scores = []
    # parse the log
    _block = int(log.block.number)
    _from = str(getattr(log.transaction, 'from_', '')).lower()
    _data = str(getattr(log.transaction, 'data', '')).lower()
    _value = int(getattr(log.transaction, 'value', ''))
    _logs = tuple(log.logs)
    # method selector
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_batching_selector(_data),
        true_score=0.9, # almost certainty
        false_score=0.5)) # not all selectors are in the wordlist: neutral
    # list of recipients
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_array_of_addresses(data=_data, min_length=min_transfer_count),
        true_score=0.7, # the list of recipients is necessary for batching, and not seen in many other types of transactions
        false_score=0.1)) # without a list of recipients, there is almost no chance the contract performs batching
    # list of amounts to transfer
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_array_of_values(data=_data, min_length=min_transfer_count),
        true_score=0.6, # low prob: the array of values could have another meaning
        false_score=0.4)) # batching can happpen without a list of values: NFT transfers or same amount for all
    # erc20 events OR erc721 events OR balance updates
    _has_any_token_transfers = (
        indicators.log_has_multiple_erc20_transfer_events(logs=_logs, min_count=min_transfer_count, min_total=min_transfer_total_erc20) # erc20
        or indicators.log_has_multiple_erc721_transfer_events(logs=_logs, min_count=min_transfer_count) # erc721
        or (
            _value >= max_batching_fee # don't go further if the sender's balance didn't move
            and indicators.transaction_value_matches_input_arrays(value=_value, data=_data, min_count=min_transfer_count, tolerance=max_batching_fee))) # only called if there are no ERC20 / ERC721 events (net opt)
    _scores.append(probabilities.indicator_to_probability(
        indicator=_has_any_token_transfers,
        true_score=0.8, # a list of transfers almost certainly means batching
        false_score=0.2)) # it's possible the transfered token doesn't follow standards and did not emit an event
    return probabilities.conflation(_scores)

# MALICIOUS ###################################################################

#TODO: "to" address keeps tokens (instead of redistributing them)

def malicious_score(
    log: TransactionEvent,
    w3: Web3,
    min_transfer_count: int=options.MIN_TRANSFER_COUNT,
    max_batching_fee: int=options.MAX_BATCHING_FEE[1]
) -> float:
    """Evaluate the provabability that a batch transaction is malicious."""
    _scores = []
    _logs = tuple(log.logs)
    # transfer of amount 0
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.log_has_erc20_transfer_of_null_amount(logs=_logs),
        true_score=0.9, # certainty
        false_score=0.5)) # neutral
    return probabilities.conflation(_scores)
