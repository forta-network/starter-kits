"""Test the extraction of arrays from the hex input data."""

import pytest
import re

import src.parsing.inputs as inputs
import tests.test_data as data

# FIXTURES ####################################################################

DATA = [_t.transaction.data for _t in data.TRANSACTIONS['batch']['ft'] + data.TRANSACTIONS['batch']['native']]
ADDRESSES = ['0x04ae3226c80e8c04d35e6e56089345bdd06da6de', '0xc5ac25cfc2b8284e84ca47dad21cf1319f732c11', '0x79dbe9bbde91a35fa8148a14084979a531fe57ea', '0x3b1ea5b11d12452693f9bd290ac2100394e6850f', '0x682dcf2f4a6e46c222927a54529b4965fb313bf2', '0xbc48cd3265fd6d6cd413cd3e7082c27993baf8b2', '0x62494b3ed9663334e57f23532155ea0575c487c5', '0x164c2b90f83b67d897ff00899695430841e38536', '0x1bcf9edb72f7650dfcdc59ae3b8a73d35a2f2902', '0x259a2795624b8a17bc7eb312a94504ad0f615d1e', '0x728ad672409da288ca5b9aa85d1a55b803ba97d7', '0x1695ce70da4521cb94dea036e6ebcf1e8a073ee6', '0x1c39e47a2968f166a11c4af9088dd45ccd13b13d', '0x961d2b694d9097f35cfffa363ef98823928a330d', '0x289e90e739a797ca53319e7a225a15f587e16d4f', '0x01b09c9a2a67a829b5d54affd0233821b43632a5', '0x4f4e0f2cb72e718fc0433222768c57e823162152', '0x0de0dd63d9fb65450339ef27577d4f39d095eb85', '0x327bb6e6fff2c05e542c63b0fcfdd270734738ef', '0x54b5ae5ebe86d2d86134f3bb7e36e7c83295cbcb', '0x360f85f0b74326cddff33a812b05353bc537747b', '0x3b135dbf827508d8ed170548f157bdcd2dc857d3', '0xb4f89d6a8c113b4232485568e542e646d93cfab1', '0x7e015972db493d9ba9a30075e397dc57b1a677da', '0x4a33862042d004d3fc45e284e1aafa05b48e3c9c', '0x4f4e0f2cb72e718fc0433222768c57e823162152', '0x50ae462a6b05c72e48dcf683a651e3d06cde4100', '0xbead32e8d8fb4fae7b08c4b3253b3cfe05e2c0de', '0xee001c024fdc16bc24638a579a52732189c7cb0d', '0x3d2b9f6a5ae61be1dfc52d9b1f807caeab60cdde', '0xed4086231fac17e04cb478448ae1439c57820b4d']

# DECODING ####################################################################

def test_chunk_string():
    assert list(inputs.chunk(DATA[0][10:], 64))
    assert all([len(_c) == 64 for _c in inputs.chunk(DATA[1][10:], 64)])

def test_max_array_length_positive_on_valid_data():
    assert all([inputs.max_array_length(_d) > 0 for _d in DATA])

def test_max_array_length_negative_or_null_on_empty_input():
    assert inputs.max_array_length('0xa9059cbb') <= 0

def test_address_validation(): # addresses and values are exclusive
    assert all([inputs.is_valid_address(_a) for _a in ADDRESSES])
    assert not inputs.is_valid_address('0x00000000000e8c04d35e6e56089345bdd06da6de')

def test_value_validation(): # addresses and values are exclusive
    assert all([not inputs.is_valid_value(_a) for _a in ADDRESSES])
    assert inputs.is_valid_value('0x00000000000e8c04d35e6e56089345bdd06da6de')

def test_array_length_matches_number_of_elements():
    _chopped_array = '000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000007f3eaa03c2deb2b909b7ff5ecf4a20f540ab1de0000000000000000000000004c956623424394c5dc4fd71f04bb28ee117b496f00000000000000000000000077d880c57f0aafea9f41405098dbe60b538cfa750000000000000000000000004eaec98a381fb95067278b1bec977b83a501dd2f000000000000000000000000380846d771c1fc8a0f7724ee98f86e2127474239'
    assert not inputs.is_valid_array(data=_chopped_array, check=inputs.is_valid_address, length=0xb)

def test_parsed_address_format():
    _raw = '00000000000000000000000007f3eaa03c2deb2b909b7ff5ecf4a20f540ab1de'
    assert type(inputs.parse_address(_raw)) == str
    assert len(inputs.parse_address(_raw)) == 42 # 20 bytes + the prefix
    assert inputs.parse_address(_raw)[:2] == '0x'

def test_parsed_value_format():
    _raw = '0000000000000000000000000000000000000000000000137b52b3b3c99e4000'
    assert type(inputs.parse_value(_raw)) == int

def test_parsed_array_format():
    _raw = '000000000000000000000000000000000000000000000000000000000000000500000000000000000000000007f3eaa03c2deb2b909b7ff5ecf4a20f540ab1de0000000000000000000000004c956623424394c5dc4fd71f04bb28ee117b496f00000000000000000000000077d880c57f0aafea9f41405098dbe60b538cfa750000000000000000000000004eaec98a381fb95067278b1bec977b83a501dd2f000000000000000000000000380846d771c1fc8a0f7724ee98f86e2127474239'
    assert type(inputs.parse_array(_raw, inputs.parse_address)) == list
    assert all([inputs.is_valid_address(_e) for _e in inputs.parse_array(_raw, inputs.parse_address)])
    assert all([type(_e) == int for _e in inputs.parse_array(_raw, inputs.parse_value)])

# REGEX #######################################################################

def test_address_regex_match_batch_input_data():
    _re = re.compile(inputs.address_regex())
    assert all([_re.findall(_d) for _d in DATA])

def test_value_regex_match_batch_input_data():
    _re = re.compile(inputs.value_regex())
    assert all([_re.findall(_d) for _d in DATA])

def test_array_length_regex_match_batch_input_data():
    for _d in DATA:
        _re = re.compile(inputs.array_length_regex(length=inputs.max_array_length(_d), exact=False))
        assert _re.findall(_d)

def test_array_regex_match_batch_input_data():
    _data = []
    for _d in DATA:
        _lengths = inputs.get_array_length_candidates(data=_d)
        for _l in _lengths:
            _re = re.compile(inputs.array_regex(length=_l, element_regex=inputs.address_regex()))
            _data.append(_re.findall(_d))
    assert any(_data) # not all batch transactions have arrays in their inputs

# PARSING #####################################################################

def test_find_array_length_in_batch_data():
    assert all([inputs.get_array_length_candidates(data=_d) for _d in DATA])

def test_find_arrays_in_batch_data():
    assert any([inputs.get_array_of_address_candidates(data=_d) for _d in DATA]) # not all batch transactions have array inputs
    assert any([inputs.get_array_of_value_candidates(data=_d) for _d in DATA]) # not all batch transactions have array inputs
