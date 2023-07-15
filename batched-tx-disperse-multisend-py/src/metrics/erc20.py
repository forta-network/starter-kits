"""Evaluate the probability that a transaction resulted in transfers of ERC20 tokens."""

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src.metrics._indicators as indicators
import src.metrics._probabilities as probabilities
import src.options as options

# CONFIDENCE ##################################################################

# TODO: add ERC115

def confidence_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the probability that a transaction handled ERC20 tokens."""
    _scores = []
    # events
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.log_has_multiple_erc20_transfer_events(log=log, floor=options.MIN_TRANSFER_COUNT),
        true_score=0.9, # certainty
        false_score=0.2)) # the token could follow another std
    return probabilities.conflation(_scores)

# MALICIOUS ###################################################################

# TODO: the ERC20 balance of the contract increased

def malicious_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the provabability that an ERC20 transaction is malicious."""
    _scores = []
    return probabilities.conflation(_scores)
