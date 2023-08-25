"""Parse HEX input data for arrays of addresses and amounts

Address and value regex are designed to be exclusive.
This avoids matching the address when searching for values and vice-versa.

All array functions are generic:
The result depends on the functions given as argument to process each element.
"""

import functools
import re

# GENERIC #####################################################################

def chunk(l, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

# DECODING ####################################################################

@functools.lru_cache(maxsize=128)
def max_array_length(data: str) -> int:
    """Calculate the max length of an array based on the length of the data string."""
    # 74 = 10 + 64 = prefix + selector + 32 bytes (uint256) for the array length
    return int((len(data) - 74) / 64) # negative or null if the data string is not long enough

@functools.lru_cache(maxsize=128)
def is_valid_address(data: str) -> bool:
    """Checks whether a hex string is mostly non-zero."""
    return len(hex(int(data, 16))) > 32 # counting the prefix 0x

@functools.lru_cache(maxsize=128)
def is_valid_value(data: str) -> bool:
    """Checks whether a hex string represents a meaningful monetary amount."""
    return len(hex(int(data, 16))) <= 32 # counting the prefix 0x

@functools.lru_cache(maxsize=128)
def is_valid_array(data: str, check: callable, length: int) -> bool:
    """Checks whether a hex string is an array."""
    _chunks = list(chunk(data, 64))
    _valid = len(data) >= 128 # array length + at least 1 element = 64 + 64 = 2 * 32 bytes
    _valid = _valid and len(data) % 64 == 0 # correct ABI encoding
    _valid = _valid and int(_chunks[0], 16) == len(_chunks) - 1 # the first word is the array length
    _valid = _valid and int(_chunks[0], 16) >= length # ignore small arrays
    _valid = _valid and all([check(_c) for _c in _chunks[1:]]) # all the elements are addresses
    return _valid

@functools.lru_cache(maxsize=128)
def parse_address(data: str) -> str:
    """Format a raw word into a 20 byte address."""
    return '0x' + data[24:]

@functools.lru_cache(maxsize=128)
def parse_value(data: str) -> int:
    """Format a raw word into an integer."""
    return int(data, 16)

@functools.lru_cache(maxsize=128)
def parse_array(data: str, parse_element: callable) -> list:
    """Format raw input data into a list of 20 bytes addresses."""
    _chunks = list(chunk(data, 64))
    return [parse_element(_c) for _c in _chunks[1:]] # omit the array length

# REGEX #######################################################################

@functools.lru_cache(maxsize=128)
def address_regex() -> str:
    """Regex matching a single address."""
    return r'0{24}[0-9a-f]{40}'

@functools.lru_cache(maxsize=128)
def value_regex() -> str:
    """Regex matching a single value."""
    return r'0{34}[0-9a-f]{30}' # 10^12 amount with 24 decimals is 0xc097ce7bc90715b34b9f1000000000, length 30

@functools.lru_cache(maxsize=128)
def array_length_regex(length: int, exact: bool=False) -> str:
    """Regex matching a low number that could be an array length."""
    _length = hex(length)[2:] # remove the prefix 0x
    _regex = '0' * (64 - len(_length)) # 0 padding on the left
    _regex += _length if exact else f'[0-9a-f]{{{len(_length)}}}'
    return _regex

@functools.lru_cache(maxsize=128)
def array_regex(length: int, element_regex: str) -> str:
    """Regex matching an entire array of addresses."""
    _length_re = array_length_regex(length=length, exact=True)
    _elements_re = '(?:' + element_regex + f'){{{length}}}' # do not capture elements individually
    return '(' + _length_re + _elements_re + ')' # only capture the whole array as a group

# PARSING #####################################################################

@functools.lru_cache(maxsize=128)
def get_array_length_candidates(data: str) -> list:
    """Extract the words in the data that could encode an array length."""
    _limit = max_array_length(data)
    _chunks = [int(_c, 16) for _c in chunk(data[10:], 64)] # ignore the prefix and selector
    return list(set([_c for _c in _chunks if _c <= _limit])) # remove repeats

@functools.lru_cache(maxsize=128)
def get_array_candidates(data: str, element_regex: str, element_check: callable, parse_element: callable, min_length: int=4) -> list:
    """Extract the address & value arrays from the hex input."""
    _arrays = []
    _length_candidates = get_array_length_candidates(data)
    for _l in _length_candidates:
        _array_re = re.compile(array_regex(length=_l, element_regex=element_regex))
        _array_candidates = _array_re.findall(data.lower())
        for _a in _array_candidates:
            if is_valid_array(data=_a, check=element_check, length=min_length):
                _arrays.append(parse_array(_a, parse_element))
    return _arrays

# HELPERS #####################################################################

@functools.lru_cache(maxsize=128)
def get_array_of_address_candidates(data: str, min_length: int=4) -> list:
    """Extract the address arrays from the hex input."""
    return get_array_candidates(
        data=data,
        element_regex=address_regex(),
        element_check=is_valid_address,
        parse_element=parse_address,
        min_length=min_length)

@functools.lru_cache(maxsize=128)
def get_array_of_value_candidates(data: str, min_length: int=4) -> list:
    """Extract the value arrays from the hex input."""
    return get_array_candidates(
        data=data,
        element_regex=value_regex(),
        element_check=is_valid_value,
        parse_element=parse_value,
        min_length=min_length)

@functools.lru_cache(maxsize=128)
def get_matching_arrays_of_address_and_value(data: str, min_length: int=4) -> list:
    """Extract arrays of addresses and values when they match."""
    _addresses = get_array_of_address_candidates(data=data, min_length=min_length)
    _values = get_array_of_value_candidates(data=data, min_length=min_length)
    return [(_a, _v) for _a in _addresses for _v in _values if len(_a) == len(_v)]
