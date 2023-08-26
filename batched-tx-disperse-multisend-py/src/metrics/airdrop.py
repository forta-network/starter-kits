"""Evaluate the probability that a transaction resulted in an airdrop."""

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
    min_transfer_total: int=options.MIN_TRANSFER_TOTAL_ERC20
) -> float:
    """Evaluate the probability that a transaction is an airdrop."""
    _scores = []
    _data = str(getattr(log.transaction, 'data', '')).lower()
    _logs = tuple(log.logs)
    # performs token transfers
    _has_token_mint_events = (
        indicators.log_has_multiple_erc20_mint_events(logs=_logs, min_count=min_transfer_count, min_total=min_transfer_total)
        or indicators.log_has_multiple_erc721_mint_events(logs=_logs, min_count=min_transfer_count))
    _scores.append(probabilities.indicator_to_probability(
        indicator=_has_token_mint_events,
        true_score=0.9, # the tokens were minted
        false_score=0.2)) # could be another standard
    # doesn't have input
    _scores.append(probabilities.indicator_to_probability(
        indicator=not indicators.input_data_has_array_of_addresses(data=_data, min_length=min_transfer_count),
        true_score=0.6, # not enough to conclude
        false_score=0.4)) # some airdrop functions take inputs
    return probabilities.conflation(_scores)

# MALICIOUS ###################################################################

# TODO: contract accumulates wealth
# TODO: new contract / new token
# TODO: contract pretends to be a known token (ex: Tether USDT)

def malicious_score(log: TransactionEvent, w3: Web3) -> float:
    """Evaluate the provabability that an airdrop is malicious."""
    _scores = []
    return probabilities.conflation(_scores)
