"""Use probability theory to score the transactions.

Given a set of probabilities {p_i}, adding another probability p will:
- leave the conflation score unchanged if p = 0.5
- increase the score if p > 0.5
- decrease the score otherwise
"""

import functools
import operator

# CAST ########################################################################

def indicator_to_probability(indicator: bool, true_score: float, false_score: float) -> float:
    """Cast a boolean indicator into a float probability."""
    return float(indicator) * true_score + (1. - float(indicator)) * false_score

# COMBINE #####################################################################

def conflation(scores: list) -> float:
    """Combine several probability scores into one, using the conflation function."""
    _inverse_scores = [1. - _x for _x in scores] # inverse probabilities
    return (
        functools.reduce(operator.mul, scores, 1.)
        / (functools.reduce(operator.mul, scores, 1.) + functools.reduce(operator.mul, _inverse_scores, 1.)))
