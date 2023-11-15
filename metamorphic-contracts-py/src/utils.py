"""Various utility functions."""

import cProfile
import datetime
import functools
import json
import logging
import os
import sys
import time

import web3

# LOGGING #####################################################################

LOG_PATTERN = '[{version} - {{levelname}}] {{message}}'

def setup_logger(level: int=logging.INFO, pattern: str=LOG_PATTERN) -> None:
    _formatter = logging.Formatter(pattern.format(version=get_bot_version()), style='{')

    _handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(level)
    _handler.setFormatter(_formatter)

    _logger = logging.getLogger()
    _logger.setLevel(level)
    _logger.addHandler(_handler)

# GENERIC #####################################################################

def get_bot_version() -> str:
    _version = ''
    with open('package.json', 'r') as _f:
        _metadata = json.load(_f)
        _version = _metadata.get('version', '')
    return _version

def load_secrets() -> None:
    with open('secrets.json', 'r') as _f:
        _secrets = json.load(_f)
        os.environ['ZETTABLOCK_API_KEY'] = _secrets.get('ZETTABLOCK_API_KEY', '')

# DATA ########################################################################

def strip_hex_prefix(data: str) -> str:
    return data[2:] if data and data[:2] == '0x' else data

def format_address_with_checksum(address: str) -> str:
    __address = strip_hex_prefix(address) if address else ''
    if __address:
        __address = '0x{0:0>40}'.format(__address.lower())
        __address = web3.Web3.toChecksumAddress(__address)
    return __address

# PROFILING ###################################################################

def timeit(func: callable) -> callable:
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        _start = time.perf_counter()
        _result = func(*args, **kwargs)
        _delta = 1000. * (time.perf_counter() - _start)
        logging.debug(f'{func.__name__} took {_delta:.9f} ms')
        return _result
    return _wrapper

def profile(func: callable) -> callable:
    @functools.wraps(func)
    def _profile(*args, **kwargs):
        _profiler = cProfile.Profile()
        _profiler.enable()
        _result = func(*args, **kwargs)
        _profiler.disable()
        _profiler.dump_stats(f'{func.__name__}')
        return _result
    return _profile
