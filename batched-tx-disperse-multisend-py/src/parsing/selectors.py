"""Generate potential selectors for the target batching methods
Ex:
- multisendEther(address[],uint256[])
- bulkTransferToken(address,address[],uint[])
"""

import itertools
import web3

# DEFAULT ARGUMENTS ###########################################################

# TODO: add optional suffix "from"
# TODO: add optional prefix "safe"
# TODO: add optional argument "_from"
# TODO: "transfer(address[],address[],address[],uint256[])" => transfer(token,from,to,amount)
PATTERNS = (
    '{verb}{adjective}{token}{noun}{args}',
    '{adjective}{verb}{token}{noun}{args}',)

# TODO: sort signatures by action (batch, airdrop, etc)
VERBS = (
    '',
    'Multisend',
    'Disperse',
    'Dispatch',
    'Send',
    'Batch',
    'Bundle',
    'Multicall')

ADJECTIVES = (
    '',
    'Multi',
    'Multiple',
    'Bulk',
    'Batched',
    'Bundled',
    'Batch',
    'Bundle',
    'Mass')

# TODO: sort signatures by token
TOKENS = ('', 'ETH', 'Eth', 'Ether', 'Token', 'Coin', 'NFT', 'Nft', 'ERC20', 'Erc20', 'ERC721', 'Erc721')

NOUNS = ('', 'Sender', 'Transfer', 'Transaction')

# TODO: add argument pattern
# TODO: single value for all addresses
ARGS = (
    '(address,address[],uint256[])',
    '(address,uint256[],address[])',
    '(address[],uint256[],address)',
    '(uint256[],address[],address)',
    '(address[],uint256[])',
    '(uint256[],address[])',
    '(address,address[],uint[])',
    '(address,uint[],address[])',
    '(address[],uint[],address)',
    '(uint[],address[],address)',
    '(address[],uint[])',
    '(uint[],address[])')

# WORDLIST GENERATION #########################################################

def generate_signature_wordlist(
    pattern: tuple=PATTERNS[0],
    verbs: tuple=VERBS,
    adjectives: tuple=ADJECTIVES,
    tokens: tuple=TOKENS,
    nouns: tuple=NOUNS,
    args: tuple=ARGS
) -> list:
    """Generate a list of plausible method signatures."""
    _signatures = []
    for _a in itertools.product(verbs, adjectives, tokens, nouns, args):
        _signature = pattern.format(verb=_a[0], adjective=_a[1], token=_a[2], noun=_a[3], args=_a[-1])
        _signature = _signature[0].lower() + _signature[1:] # camel case
        _signatures.append(_signature)
        #_signatures.append((web3.Web3.keccak(text=_signature).hex())[:10]) # 0x + first 4 bytes of the hash
    return _signatures

# SELECTOR ####################################################################

def selector(signature: str) -> str:
    """Compute the web3 method selector for a single signature."""
    return (web3.Web3.keccak(text=signature).hex().lower())[:10] # "0x" prefix + 4 bytes
