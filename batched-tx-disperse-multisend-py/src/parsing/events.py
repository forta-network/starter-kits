"""Filter the logs for relevant ERC20 / ERC721 events."""

import copy
import functools
import itertools
import json
import logging

from eth_abi.abi import ABICodec
from eth_utils.abi  import event_abi_to_log_topic
from hexbytes import HexBytes
from forta_agent.receipt import Log
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

def _apply_indexation_mask(abi: ABIEvent, mask: tuple) -> ABIEvent:
    """Change the "indexed" field of the ABI according to the mask."""
    _abi = copy.deepcopy(abi)
    for _i in range(len(mask)):
        _abi['inputs'][_i]['indexed'] = mask[_i]
    return _abi

def _generate_all_abi_indexation_variants(abi: ABIEvent) -> dict:
    """Generate all the variants of the ABI by switching each "indexed" field true / false for the inputs."""
    _count = len(abi.get('inputs', ()))
    _indexed = tuple(itertools.product(*(_count * ((True, False), ))))
    _abis = {_c: [] for _c in range(_count + 1)} # order by number of indexed inputs
    for _i in _indexed: # each indexation variant
        _abis[sum(_i)].append(_apply_indexation_mask(abi=abi, mask=_i))
    return _abis

def _generate_the_most_probable_abi_indexation_variants(abi: ABIEvent) -> dict:
    """Generate the most probable variant of the ABI for each count of indexed inputs."""
    _count = len(abi.get('inputs', ()))
    _indexed = tuple((_i * [True] + (_count - _i) * [False]) for _i in range(_count + 1)) # index from left to right, without gaps
    return {sum(_i): _apply_indexation_mask(abi=abi, mask=_i) for _i in _indexed} # order by number of indexed inputs

def _compare_abi_to_log(abi: ABIEvent, log: Log) -> bool:
    """Returns True if abit and log match, False otherwise."""
    return (
        bool(log['topics'])
        and event_abi_to_log_topic(abi) == log['topics'][0])

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
    _abi_variants = _generate_the_most_probable_abi_indexation_variants(abi=abi)

    @functools.lru_cache(maxsize=128)
    def _get_event_data(logs: tuple) -> list:
        """Extract event data from the hex log topics."""
        _results = []
        for _log in logs:
            _log.topics = [HexBytes(_topic) for _topic in _log.topics]
            if _compare_abi_to_log(abi=abi, log=_log): # avoid MismatchedABI exception
                _abi = _abi_variants.get(len(_log['topics']) - 1, None) # avoid LogTopicError exception
                if _abi:
                    _results.append(get_event_data(codec, _abi, _log))
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
