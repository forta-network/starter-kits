"""Evaluate the probability that a transaction resulted in an airdrop."""

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src.metrics._indicators as indicators
import src.metrics._probabilities as probabilities
import src.options as options

# CONFIDENCE ##################################################################

def confidence_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the probability that a transaction is an airdrop."""
    _scores = []
    _data = str(getattr(log.transaction, 'data', '')).lower()
    # performs token transfers
    _has_token_transfer_events = (
        indicators.log_has_multiple_erc20_transfer_events(log=log, floor=2*options.MIN_TRANSFER_COUNT)
        or indicators.log_has_multiple_erc721_transfer_events(log=log, floor=2*options.MIN_TRANSFER_COUNT))
    _scores.append(probabilities.indicator_to_probability(
        indicator=_has_token_transfer_events,
        true_score=0.6, # required, but not enough to conclude
        false_score=0.2)) # could be another standard
    # doesn't have input
    _scores.append(probabilities.indicator_to_probability(
        indicator=not indicators.input_data_has_array_of_addresses(_data),
        true_score=0.6, # not enough to conclude
        false_score=0.4)) # some airdrop functions take inputs
    return probabilities.conflation(_scores)

# MALICIOUS ###################################################################

# TODO: contract accumulates wealth
# TODO: new contract / new token

def malicious_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the provabability that an airdrop is malicious."""
    _scores = []
    return probabilities.conflation(_scores)
