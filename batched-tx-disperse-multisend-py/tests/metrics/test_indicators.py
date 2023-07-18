"""Test the boolean indicators."""

import pytest

import src.metrics._indicators as indicators
import tests.test_data as data

# FIXTURES ####################################################################

TX_TO = [_t.transaction.to for _t in data.TRANSACTIONS['batch']['ft'] + data.TRANSACTIONS['batch']['native']]
TX_DATA_BATCH = [_t.transaction.data for _t in data.TRANSACTIONS['batch']['ft'] + data.TRANSACTIONS['batch']['native']]
TX_DATA_RANDOM = [_t.transaction.data for _t in data.TRANSACTIONS['random']['any']]

# SELECTORS ###################################################################

def test_indicators_detect_transaction_calls_to_known_methods():
    assert any([indicators.input_data_has_batching_selector(_d) for _d in TX_DATA_BATCH]) # not all live transaction have known selectors

def test_indicators_ignore_transaction_calls_to_random_methods():
    assert all([not indicators.input_data_has_batching_selector(_d) for _d in TX_DATA_RANDOM])

# INPUT DATA ##################################################################

def test_indicators_detect_arrays_in_input_data():
    assert(any([indicators.input_data_has_array_of_addresses(data=_d, min_length=4) for _d in TX_DATA_BATCH])) # not all batch transactions have input data
    assert(any([indicators.input_data_has_array_of_values(data=_d, min_length=4) for _d in TX_DATA_BATCH])) # not all batch transactions have input data

def test_indicators_ignore_other_data_types():
    assert(any([not indicators.input_data_has_array_of_addresses(data=_d, min_length=4) for _d in TX_DATA_RANDOM])) # some random transactions have input arrays too
    assert(any([not indicators.input_data_has_array_of_values(data=_d, min_length=4) for _d in TX_DATA_RANDOM])) # some random transactions have input arrays too

# EVENTS ######################################################################

# TRANSFERS ###################################################################
