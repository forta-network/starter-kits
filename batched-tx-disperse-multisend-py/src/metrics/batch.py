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
    # list of recipients and amounts with same length
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_matching_arrays_of_values_and_addresses(data=_data, min_length=min_transfer_count),
        true_score=0.8, # having both lists is necessary, and rarely seen in other transactions
        false_score=0.1)) # without lists of recipients and amounts, there is little chance the contract performs batching
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
