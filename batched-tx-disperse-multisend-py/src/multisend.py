"""Utilities to decode Multisend data"""

from json import loads
from web3 import Web3

from src.options import TARGET_TOKEN

# CONSTANTS ###################################################################

ADDRESS = Web3.toChecksumAddress('0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe')
ABI = loads('[{"inputs":[{"internalType":"address[]","name":"recipients","type":"address[]"},{"internalType":"uint256[]","name":"values","type":"uint256[]"}],"name":"multisendEther","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"contract IERC20","name":"token","type":"address"},{"internalType":"address[]","name":"recipients","type":"address[]"},{"internalType":"uint256[]","name":"values","type":"uint256[]"}],"name":"multisendToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]')
METHODS = ['multisendToken', 'multisendEther']

# SCANNER #####################################################################

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
        return False

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
