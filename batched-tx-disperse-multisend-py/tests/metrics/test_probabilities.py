"""Test the generic probability functions."""

import pytest
import random

import src.metrics._probabilities as probabilities
import tests.test_data as data

# FIXTURES ####################################################################

SCORES = [random.uniform(0., 1.) for _ in range(100)]
SAMPLES = [random.sample(SCORES, random.randint(1,10)) for _ in range(100)]

# CASTING #####################################################################

def test_cast_value_matches_the_indicator():
    assert all([probabilities.indicator_to_probability(True, _s, 1. - _s) == _s for _s in SCORES])
    assert all([probabilities.indicator_to_probability(False, _s, 1. - _s) == (1. - _s) for _s in SCORES])

# CONFLATION ##################################################################

def test_conflation_is_the_identity_on_list_of_length_1():
    assert all([probabilities.conflation([_s]) for _s in SCORES])

def test_conflation_score_increases_when_adding_a_probability_above_50_percent():
    assert all([probabilities.conflation(_s + [random.uniform(0.51, 0.99)]) > probabilities.conflation(_s) for _s in SAMPLES])

def test_conflation_score_remains_the_same_when_adding_a_probability_of_50_percent():
    assert all([probabilities.conflation(_s + [0.5]) == probabilities.conflation(_s) for _s in SAMPLES])

def test_conflation_score_dcreases_when_adding_a_probability_below_50_percent():
    assert all([probabilities.conflation(_s +[ random.uniform(0.01, 0.49)]) < probabilities.conflation(_s) for _s in SAMPLES])
