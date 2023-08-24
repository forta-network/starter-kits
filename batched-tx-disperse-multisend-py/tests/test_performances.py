"""Test the agent on a fork"""

import pstats
import web3

import src.agent as agent
import src.utils as utils
import tests.test_data as data

# PROFILING ###################################################################

_w3 = web3.Web3(web3.EthereumTesterProvider())
_handle = agent.handle_transaction_factory(w3=_w3)

@utils.profile
def test_performances() -> None:
    return [_handle(_t) for _t in data.ALL_TRANSACTIONS]

def display_performances() -> None:
    _p = pstats.Stats('test_performances')
    _p.strip_dirs().sort_stats('cumulative').print_stats()

# MAIN ########################################################################

if __name__ == '':
    test_performances()
    display_performances()
