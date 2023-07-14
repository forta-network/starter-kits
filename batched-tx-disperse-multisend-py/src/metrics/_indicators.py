"""Base indicators on transactions and their metadata."""

import src._addresses as addresses
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
    return len(inputs.get_array_of_address_candidates(data)) > 0

def input_data_has_array_of_values(data: str) -> bool:
    return len(inputs.get_array_of_value_candidates(data)) > 0

# EVENTS INDICATORS ###########################################################

# BALANCES INDICATORS #########################################################
