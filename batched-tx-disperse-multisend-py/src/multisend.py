"""Utilities to decode Multisend data"""

from json import loads
from web3 import Web3

from src.constants import TOKEN

# CONSTANTS ###################################################################

ADDRESS = Web3.toChecksumAddress('0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe')
ABI = loads('[{"inputs":[{"internalType":"address[]","name":"recipients","type":"address[]"},{"internalType":"uint256[]","name":"values","type":"uint256[]"}],"name":"multisendEther","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"contract IERC20","name":"token","type":"address"},{"internalType":"address[]","name":"recipients","type":"address[]"},{"internalType":"uint256[]","name":"values","type":"uint256[]"}],"name":"multisendToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]')
METHODS = ['multisendToken']

# SCANNER #####################################################################

def parse_transaction_input_factory(w3: Web3, token: str=TOKEN):
    _contract = w3.eth.contract(address=ADDRESS, abi=ABI)
    def _parse(data: str):
        _txs = []
        try: # in case the input data is corrupted
            _f, _args = _contract.decode_function_input(data)
            _fn = _f.fn_name
        except Exception as e:
            _fn = ''
            _args = {}
        if _fn in METHODS: # only consider ERC20 transactions
            if token in _args.get('token', ''): # works also when there's no filter on the token, IE token = ''
                _txs = list(zip(_args.get('recipients', []), _args.get('values', [])))
        return _txs
    return _parse
