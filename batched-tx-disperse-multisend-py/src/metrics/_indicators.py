"""Base indicators on transactions and their metadata."""

from itertools import chain

from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src._balances as balances
import src._events as events
import src._inputs as inputs
import src._selectors as selectors

# SELECTORS INDICATORS ########################################################

KNOWN_SIGNATURES = (
    selectors.generate_signature_wordlist(pattern=selectors.PATTERNS[0], verbs=selectors.VERBS, adjectives=selectors.ADJECTIVES, tokens=selectors.TOKENS, nouns=selectors.NOUNS, args=selectors.ARGS)
    + selectors.generate_signature_wordlist(pattern=selectors.PATTERNS[1], verbs=selectors.VERBS, adjectives=selectors.ADJECTIVES, tokens=selectors.TOKENS, nouns=selectors.NOUNS, args=selectors.ARGS))

KNOWN_SELECTORS = {selectors.selector(_s): _s for _s in KNOWN_SIGNATURES}

def input_data_has_batching_selector(data: str, known: dict=KNOWN_SELECTORS) -> bool:
    return data[:10].lower() in known # selector => signature mapping

# INPUTS INDICATORS ###########################################################

def input_data_has_array_of_addresses(data: str) -> bool:
    return len(inputs.get_array_of_address_candidates(data=data, min_length=4)) > 0 # at least one candidate array

def input_data_has_array_of_values(data: str) -> bool:
    return len(inputs.get_array_of_value_candidates(data=data, min_length=4)) > 0 # at least one candidate array

# EVENTS INDICATORS ###########################################################

# TODO: add ERC1155

def log_has_multiple_erc20_transfer_events(log: TransactionEvent, floor: int) -> bool:
    return len(events.parse_log(log=log, abi=events.ERC20_TRANSFER_EVENT)) >= floor

def log_has_multiple_erc721_transfer_events(log: TransactionEvent, floor: int) -> bool:
    return len(events.parse_log(log=log, abi=events.ERC721_TRANSFER_EVENT)) >= floor

# BALANCES INDICATORS #########################################################

def multiple_native_token_balances_changed(w3: Web3, data: str, block: int, floor: int) -> bool:
    _recipients = chain.from_iterable(inputs.get_array_of_address_candidates(data=data, min_length=floor)) # list of candidates = list of lists
    _deltas = [balances.get_balance_delta(w3=w3, address=_a, block=block) for _a in _recipients] # _recipients is now a flat list
    return len(_deltas) >= floor

def native_token_balance_changed(w3: Web3, address: str, block: int, tolerance: int=10**17) -> bool:
    return balances.get_balance_delta(w3=w3, address=address, block=block) > tolerance # in case the contract has a fee, set to 0.1 EHT by default
