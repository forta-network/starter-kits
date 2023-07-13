"""Evaluate the probability that multiple transfers were bundled in a transaction."""

import src.metrics._indicators as indicators
import src.metrics._probabilities as probabilities

# CONFIDENCE ##################################################################

def confidence_score(recipient: str, data: str) -> float:
    """Evaluate the probability that multiple transfers were bundled in a transaction."""
    _scores = []
    # to address
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.address_is_known_contract(recipient),
        true_score=0.9, # known addresses make it a near certainty
        false_score=0.5)) # unknown addresses are neutral
    # method selector
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_batching_selector(data),
        true_score=0.9, # almost certainty
        false_score=0.5)) # not all selectors are in the wordlist: neutral
    # list of recipients
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_array_of_addresses(data),
        true_score=0.7, # the list of recipients is necessary for batching, and not seen in many other types of transactions
        false_score=0.1)) # without a list of recipients, there is almost no chance the contract performs batching
    # list of amounts to transfer
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.input_data_has_array_of_values(data),
        true_score=0.6, # low prob: the array of values could have another meaning
        false_score=0.4)) # batching can happpen without a list of values: NFT transfers or same amount for all
    return probabilities.conflation(_scores)

# ANOMALY #####################################################################

# events differ from input data

def anomaly_score(recipient: str, data: str) -> float:
    """Evaluate."""
    _scores = []
    _scores.append(probabilities.indicator_to_probability(
        indicator=indicators.address_is_known_contract(recipient) and not indicators.input_data_has_batching_selector(data),
        true_score=0.7, # slightly
        false_score=0.5)) # neutral if false
    return probabilities.conflation(_scores)
