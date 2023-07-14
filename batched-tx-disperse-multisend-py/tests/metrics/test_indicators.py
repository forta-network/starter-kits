"""Test the boolean indicators."""

import pytest

import src.metrics._indicators as indicators
import tests.test_data as data

# FIXTURES ####################################################################

TX_TO = [_t.transaction.to for _t in data.TRANSACTIONS['batch-erc20-token'] + data.TRANSACTIONS['batch-native-token']]
TX_DATA_BATCH = [_t.transaction.data for _t in data.TRANSACTIONS['batch-erc20-token'] + data.TRANSACTIONS['batch-native-token']]
TX_DATA_RANDOM = [_t.transaction.data for _t in data.TRANSACTIONS['random']]

# SELECTORS ###################################################################

def test_indicators_detect_transaction_calls_to_known_methods():
    assert all([indicators.input_data_has_batching_selector(_d) for _d in TX_DATA_BATCH])

def test_indicators_ignore_transaction_calls_to_random_methods():
    assert all([not indicators.input_data_has_batching_selector(_d) for _d in TX_DATA_RANDOM])

# INPUT DATA ##################################################################

def test_indicators_detect_arrays_in_input_data():
    assert(all([indicators.input_data_has_array_of_addresses(_d) for _d in TX_DATA_BATCH]))
    assert(all([indicators.input_data_has_array_of_values(_d) for _d in TX_DATA_BATCH]))

def test_indicators_ignore_other_data_types():
    assert(all([not indicators.input_data_has_array_of_addresses(_d) for _d in TX_DATA_RANDOM]))
    assert(all([not indicators.input_data_has_array_of_values(_d) for _d in TX_DATA_RANDOM]))

# EVENTS ######################################################################

# TRANSFERS ###################################################################
