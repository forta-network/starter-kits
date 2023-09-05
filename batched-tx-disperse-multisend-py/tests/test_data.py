"""Historic blockchain data"""

import itertools
import os
import pickle

import forta_agent

# TOKENS ######################################################################

TOKENS = {
    'ETH': '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    'Тether USD (USDТ)': '0xdac17f958d2ee523a2206206994597c13d831ec7', # fake, used for phishing
    'ETH (ETH)': '0xb23a19d28a7e9bdec030782346b0d9ace11530f5'} # fake too

# TRANSACTIONS ################################################################

TRANSACTIONS = {
    'random': {
        'any': []},
    'batch': {
        'ft': [],
        'nft': [],
        'native': []}, 
    'airdrop': {
        'ft': [],
        'nft': []}}

for _root, _, _files in os.walk('tests/.data/'):
    for _filename in sorted(_files):
        _parent = _root.split(os.sep)
        _token = _parent[-1]
        _type = _parent[-2]
        _path = os.path.join(*_parent, _filename)
        with open(_path, 'rb') as _f:
            TRANSACTIONS[_type][_token].append(pickle.load(_f))

# ALL #########################################################################

ALL_TRANSACTIONS = tuple(itertools.chain.from_iterable([TRANSACTIONS[_type][_token] for _type in TRANSACTIONS for _token in TRANSACTIONS[_type]]))
