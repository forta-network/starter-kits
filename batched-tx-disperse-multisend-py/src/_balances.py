"""Track the evolution of native token balances."""

from web3 import Web3

# DELTA #######################################################################

# TODO: cache the requests
def get_balance_delta(w3: Web3, address: str, block: int) -> int:
    """Calculate the difference in balance before / after a given block."""
    _before = _after = 0
    if address:
        _before = w3.eth.get_balance(Web3.toChecksumAddress(address), block - 1)
        _after = w3.eth.get_balance(Web3.toChecksumAddress(address), block)
    return _after - _before
