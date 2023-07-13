"""Utilities to decode Disperse data"""

from json import loads
from web3 import Web3

from src.options import TARGET_TOKEN

# CONSTANTS ###################################################################

ADDRESS = Web3.toChecksumAddress('0xd152f549545093347a162dce210e7293f1452150')
ABI = loads('[{"constant":false,"inputs":[{"name":"token","type":"address"},{"name":"recipients","type":"address[]"},{"name":"values","type":"uint256[]"}],"name":"disperseTokenSimple","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"token","type":"address"},{"name":"recipients","type":"address[]"},{"name":"values","type":"uint256[]"}],"name":"disperseToken","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"recipients","type":"address[]"},{"name":"values","type":"uint256[]"}],"name":"disperseEther","outputs":[],"payable":true,"stateMutability":"payable","type":"function"}]')
METHODS = ['disperseToken', 'disperseTokenSimple', 'disperseEther']

# PARSER ######################################################################

def parse_transaction_input_factory(w3: Web3, token: str=TARGET_TOKEN) -> callable:
    _contract = w3.eth.contract(address=ADDRESS, abi=ABI)

    def _decode_function_input(data: str) -> tuple:
        _fn = ''
        _args = {}
        try:
            _f, _args = _contract.decode_function_input(data)
            _fn = _f.fn_name
        except Exception: # in case the input data is corrupted / meant for another contract
            pass
        return _fn, _args

    def _is_manual_call(method: str) -> bool:
        return method == 'disperseTokenSimple'

    def _parse_batched_transactions(method: str, arguments: dict, target: str) -> tuple:
        _token = arguments.get('token', '').lower() # empty in case of a native token like ETH / MATIC / etc
        _txs = []
        if method in METHODS: # only consider ERC20 transactions
            if target.lower() in _token: # works also when there's no filter on the token, IE token = ''
                _txs = list(zip(arguments.get('recipients', []), arguments.get('values', [])))
        return _token, _txs

    def _parse(data: str) -> tuple:
        # parse hex input data from the transaction
        _fn, _args = _decode_function_input(data)
        # keep only calls to the batching methods
        _token, _txs = _parse_batched_transactions(method=_fn, arguments=_args, target=token)
        # check whether the call is made through a web app or manually
        _manual = _is_manual_call(method=_fn)
        # return the findings
        return _token, _txs, _manual

    return _parse
