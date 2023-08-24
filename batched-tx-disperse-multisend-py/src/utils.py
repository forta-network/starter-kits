"""Various utility functions."""

import datetime
import json
import logging
import os
import sys

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
