"""Track the evolution of native token balances."""

import functools

from web3 import Web3

# DELTA #######################################################################

@functools.lru_cache(maxsize=128)
def get_balance_delta(w3: Web3, address: str, block: int) -> int:
    """Calculate the difference in balance before / after a given block."""
    _before = _after = 0
    if address:
        _before = w3.eth.get_balance(Web3.toChecksumAddress(address), block - 1)
        _after = w3.eth.get_balance(Web3.toChecksumAddress(address), block)
    return _after - _before

@functools.lru_cache(maxsize=128)
def get_balance_deltas(w3: Web3, addresses: list, block: int) -> dict:
    """List all the addresses that sustained a balance change."""
    _deltas = {_a: get_balance_delta(w3=w3, address=_a, block=block) for _a in addresses}
    return {_a: _d for _a, _d in _deltas.items() if abs(_d) > 0}