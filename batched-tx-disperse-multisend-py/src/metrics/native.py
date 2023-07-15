"""Evaluate the probability that a transaction resulted in transfers of native tokens."""

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src.metrics._indicators as indicators
import src.metrics._probabilities as probabilities
import src.options as options

# CONFIDENCE ##################################################################

def confidence_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the probability that a transaction resulted in transfers of native tokens."""
    _scores = []
    _from = str(getattr(log.transaction, 'from_', '')).lower()
    _data = str(getattr(log.transaction, 'data', '')).lower()
    _block = int(log.block.number)
    # "from" contract balance significantly changed
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.native_token_balance_changed(w3=w3, address=_from, block=_block, tolerance=10**17), # mvt below 0.1 ETH are ignored
        true_score=0.6, # required, but not conclusive
        false_score=0.1)) # certainty: no batch transfer without updating the sender's balance
    # check whether the balances of the input addresses have changed
    if probabilities.conflation(_scores) > 0.5: # from balance changed
        _scores.append(probabilities.indicator_to_probability(
            indicator=indicators.multiple_native_token_balances_changed(w3=w3, data=_data, block=_block, floor=options.MIN_TRANSFER_COUNT),
            true_score=0.7, # required, but not conclusive
            false_score=0.2)) # addresses specified outside of the inputs could have had their balance changed
    return probabilities.conflation(_scores)

# MALICIOUS ###################################################################

# TODO: transfers of 0 ETH

def malicious_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the provabability that the transfer is malicious."""
    _scores = []
    _to = str(getattr(log.transaction, 'to', '')).lower()
    _block = int(log.block.number)
    # "to" contract balance significantly changed
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.native_token_balance_changed(w3=w3, address=_to, block=_block, tolerance=10**17), # mvt below 0.1 ETH are ignored
        true_score=0.7, # batching contracts are not supposed to accumulate ETH
        false_score=0.5)) # neutral: could still be malicious
    return probabilities.conflation(_scores)
