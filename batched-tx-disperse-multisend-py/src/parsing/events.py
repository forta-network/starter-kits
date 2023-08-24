"""Filter the logs for relevant ERC20 / ERC721 events."""

import json

from forta_agent.transaction_event import TransactionEvent

# ABIs ########################################################################

ERC20_APPROVAL_EVENT = '{"name":"Approval","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_spender","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}]}'
ERC20_TRANSFER_EVENT = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":false,"name":"_value","type":"uint256"}]}'

ERC721_APPROVAL_EVENT = '{"name":"Approval","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_approved","type":"address"},{"indexed":true,"name":"_tokenId","type":"uint256"}]}'
ERC721_APPROVAL_FOR_ALL_EVENT = '{"name":"ApprovalForAll","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_owner","type":"address"},{"indexed":true,"name":"_operator","type":"address"},{"indexed":false,"name":"_approved","type":"bool"}]}'
ERC721_TRANSFER_EVENT = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"_from","type":"address"},{"indexed":true,"name":"_to","type":"address"},{"indexed":true,"name":"_tokenId","type":"uint256"}]}'

def _get_input_names(abi: str) -> list:
    """Extract the name of each input of an event, from its ABI."""
    return [_a.get('name', '') for _a in json.loads(abi).get('inputs', [])]

# PARSE #######################################################################

def _get_arg_value(log: 'AttributeDict', name: str) -> str:
    """Extract the value of an event input from its log.""" 
    return str(log.get('args', {}).get(name, ''))

def _get_token_address(log: 'AttributeDict') -> str:
    """Extract the address of the token that emitted the event."""
    return str((log.get('address', '')))

def _parse_event(log: 'AttributeDict', names: list) -> dict:
    """Extract the relevant data from a log and format it."""
    return {
        'token': _get_token_address(log=log),
        'from': _get_arg_value(log=log, name=names[0]),
        'to': _get_arg_value(log=log, name=names[1]),
        'value': _get_arg_value(log=log, name=names[2])}

def parse_log(log: TransactionEvent, abi: str=ERC20_TRANSFER_EVENT, filters: dict={}) -> list:
    """Extract all the event matching a given ABI."""
    _inputs = _get_input_names(abi)
    _logs = log.filter_log(abi)
    # return the args of each event in a tuple
    return [_parse_event(log=_l, names=_inputs) for _l in _logs]
