"""Filter the logs for relevant ERC20 / ERC721 events."""

import copy
import functools
import itertools
import json
import logging

from eth_abi.abi import ABICodec
from hexbytes import HexBytes
from forta_agent.transaction_event import TransactionEvent
from web3._utils.abi import build_strict_registry
from web3._utils.events import get_event_data
from web3.exceptions import LogTopicError, MismatchedABI
from web3.types import ABIEvent

# ABIs ########################################################################

# TODO variants with / without indexing

ERC20_APPROVAL_EVENT = ABIEvent(json.loads('{"name":"Approval","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_spender","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}]}'))
ERC20_TRANSFER_EVENT = ABIEvent(json.loads('{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}]}'))
ERC721_APPROVAL_EVENT = ABIEvent(json.loads('{"name":"Approval","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_approved","type":"address"},{"indexed":true,"name":"_tokenId","type":"uint256"}]}'))
ERC721_APPROVAL_FOR_ALL_EVENT = ABIEvent(json.loads('{"name":"ApprovalForAll","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_operator","type":"address"},{"indexed":false,"name":"_approved","type":"bool"}]}'))
ERC721_TRANSFER_EVENT = ABIEvent(json.loads('{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":true,"name":"_tokenId","type":"uint256"}]}'))

def _get_input_names(abi: ABIEvent) -> tuple:
    """Extract the name of each input of an event, from its ABI."""
    return tuple(_a.get('name', '') for _a in abi.get('inputs', []))

@functools.lru_cache(maxsize=128)
def _abi_codec() -> ABICodec:
    """Wrapper around the registry for encoding & decoding ABIs."""
    return ABICodec(build_strict_registry())

def _generate_all_abi_indexation_variants(abi: ABIEvent) -> tuple:
    """Generate all the variants of the input ABI by switching each "indexed" field true / false for the inputs."""
    _count = len(abi.get('inputs', ()))
    _indexed = tuple(itertools.product(*(_count * ((True, False), ))))
    _abis = tuple(copy.deepcopy(abi) for _ in range(2 ** _count))
    for _i in range(2 ** _count): # each indexation variant
        for _j in range(_count): # each input
            _abis[_i]['inputs'][_j]['indexed'] = _indexed[_i][_j]
    return _abis

# FORMAT ######################################################################

@functools.lru_cache(maxsize=128)
def _get_arg_value(event: 'AttributeDict', name: str) -> str:
    """Extract the value of an event input from its log.""" 
    return str(event.get('args', {}).get(name, ''))

@functools.lru_cache(maxsize=128)
def _get_token_address(event: 'AttributeDict') -> str:
    """Extract the address of the token that emitted the event."""
    return str((event.get('address', '')))

@functools.lru_cache(maxsize=128)
def _parse_event(event: 'AttributeDict', names: tuple) -> dict:
    """Extract the relevant data from a log and format it."""
    return {
        'token': _get_token_address(event=event),
        'from': _get_arg_value(event=event, name=names[0]),
        'to': _get_arg_value(event=event, name=names[1]),
        'value': _get_arg_value(event=event, name=names[2])}

# DECODE ######################################################################

def get_event_data_factory(abi: ABIEvent, codec: ABICodec) -> list:
    """Adapt the parsing logic to a given event."""

    @functools.lru_cache(maxsize=128)
    def _get_event_data(logs: tuple) -> list:
        """Extract event data from the hex log topics."""
        _results = []
        for _log in logs:
            _log.topics = [HexBytes(_topic) for _topic in _log.topics]
            try:
                _results.append(get_event_data(codec, abi, _log))
            except MismatchedABI: # topic and event don't match
                continue
            except LogTopicError: # topic and event match, but the args are not split between topic and data as expected ("indexed" issue)
                continue
            except Exception as e:
                logging.error(e)
                raise e
        return _results

    return _get_event_data

def parse_logs_factory(abi: ABIEvent=ERC20_TRANSFER_EVENT, codec: ABICodec=_abi_codec()) -> callable:
    """Adapt the parsing logic to a given event."""
    _inputs = _get_input_names(abi)
    _get_event_data = get_event_data_factory(abi=abi, codec=codec)

    @functools.lru_cache(maxsize=128)
    def _parse_logs(logs: tuple) -> tuple:
        """Extract all the event matching a given ABI."""
        _events = _get_event_data(logs=logs)
        # return the args of each event in a dict
        return tuple(_parse_event(event=_e, names=_inputs) for _e in _events)

    return _parse_logs

# SHORTHANDS ##################################################################

filter_logs_for_erc20_transfer_events = parse_logs_factory(abi=ERC20_TRANSFER_EVENT, codec=_abi_codec())

filter_logs_for_erc721_transfer_events = parse_logs_factory(abi=ERC721_TRANSFER_EVENT, codec=_abi_codec())
