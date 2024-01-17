"""Historic blockchain data"""

import itertools
import os
import pickle

# IO ##########################################################################

def import_data(dataset: str='transactions'):
    __data = {}
    for __root, _, __files in os.walk('tests/.data/{dataset}/'.format(dataset=dataset)):
        for __filename in sorted(__files):
            # parse the object categories
            __parent = __root.split(os.sep)
            __subtype = __parent[-1]
            __type = __parent[-2]
            __path = os.path.join(*__parent, __filename)
            # init the dictionaries
            if not __type in __data:
                __data[__type] = {}
            if not __subtype in __data[__type]:
                __data[__type][__subtype] = []
            # load the data
            with open(__path, 'rb') as __f:
                __data[__type][__subtype].append(pickle.load(__f))
    return __data

# TRANSACTIONS ################################################################

TRANSACTIONS = import_data(dataset='transactions')

# TRACES ######################################################################

TRACES = import_data(dataset='traces')

# LOGS ########################################################################

LOGS = import_data(dataset='logs')

# ALL #########################################################################

ALL_TRANSACTIONS = tuple(itertools.chain.from_iterable([TRANSACTIONS[__type][__subtype] for __type in TRANSACTIONS for __subtype in TRANSACTIONS[__type]]))

ALL_TRACES = tuple(itertools.chain.from_iterable([TRACES[__type][__subtype] for __type in TRACES for __subtype in TRACES[__type]]))

ALL_LOGS = tuple(itertools.chain.from_iterable([LOGS[__type][__subtype] for __type in LOGS for __subtype in LOGS[__type]]))
