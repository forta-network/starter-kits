"""Utilities to decode Disperse data"""

from json import loads
from web3 import Web3

from src.constants import TOKEN

# CONSTANTS ###################################################################

ADDRESS = Web3.toChecksumAddress('0xd152f549545093347a162dce210e7293f1452150')
ABI = loads('[{"constant":false,"inputs":[{"name":"token","type":"address"},{"name":"recipients","type":"address[]"},{"name":"values","type":"uint256[]"}],"name":"disperseTokenSimple","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"token","type":"address"},{"name":"recipients","type":"address[]"},{"name":"values","type":"uint256[]"}],"name":"disperseToken","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"recipients","type":"address[]"},{"name":"values","type":"uint256[]"}],"name":"disperseEther","outputs":[],"payable":true,"stateMutability":"payable","type":"function"}]')
METHODS = ['disperseToken', 'disperseTokenSimple', 'disperseEther']

# SCANNER #####################################################################

def parse_transaction_input_factory(w3: Web3, token: str=TOKEN):
    _contract = w3.eth.contract(address=ADDRESS, abi=ABI)

    def _parse(data: str):
        _token = ''
        _txs = []
        # parse hex input data from the transaction
        try: # in case the input data is corrupted /  meant for another contract
            _f, _args = _contract.decode_function_input(data)
            _fn = _f.fn_name
        except Exception as e:
            _fn = ''
            _args = {}
        finally:
            _token = _args.get('token', '').lower() # empty in case of a native token like ETH / MATIC / etc
        # keep only calls to the batching methods
        if _fn in METHODS: # only consider ERC20 transactions
            if token.lower() in _token: # works also when there's no filter on the token, IE token = ''
                _txs = list(zip(_args.get('recipients', []), _args.get('values', [])))
        return _token, _txs

    return _parse
