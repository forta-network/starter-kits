"""Evaluate the probability that a transaction resulted in transfers of native tokens."""

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
    min_transfer_total: int=options.MIN_TRANSFER_TOTAL_NATIVE,
    max_batching_fee: int=options.MAX_BATCHING_FEE[1]
) -> float:
    """Evaluate the probability that a transaction resulted in transfers of native tokens."""
    _scores = []
    _block = int(log.block.number)
    _from = str(getattr(log.transaction, 'from_', '')).lower()
    _data = str(getattr(log.transaction, 'data', '')).lower()
    _value = int(getattr(log.transaction, 'value', ''))
    # "from" contract balance significantly changed
    _scores.append(probabilities.indicator_to_probability(
        indicator=_value >= max_batching_fee, # mvt below 0.1 ETH are ignored
        true_score=0.5, # required, but not conclusive
        false_score=0.1)) # certainty: no batch transfer without updating the sender's balance
    # check whether the transaction value is sprayed (split and sent to multiple recipients)
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.transaction_value_matches_input_arrays(value=_value, data=_data, min_count=min_transfer_count, tolerance=max_batching_fee),
        true_score=0.8, # very likely: the transaction value is split among recipients specified in the inputs
        false_score=0.2)) # addresses specified outside of the inputs could have had their balance changed
    return probabilities.conflation(_scores)

# MALICIOUS ###################################################################

def malicious_score(
    log: TransactionEvent,
    w3: Web3,
    min_transfer_count: int=options.MIN_TRANSFER_COUNT,
    max_batching_fee: int=options.MAX_BATCHING_FEE[1]
) -> float:
    """Evaluate the provabability that the transfer is malicious."""
    _scores = []
    return probabilities.conflation(_scores)
