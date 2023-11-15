"""Forta agent scanning for batched transactions."""

import functools
import logging
import pprint

from forta_agent import get_json_rpc_url
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import forta_toolkit.alerts
import forta_toolkit.logging
import forta_toolkit.parsing.env
import forta_toolkit.parsing.logs
import forta_toolkit.parsing.traces
import forta_toolkit.profiling

import ioseeth.indicators.events
import ioseeth.metrics.evasion.morphing.metamorphism

import src.findings
import src.options
import src.scoring

# CONSTANTS ###################################################################

CHAIN_ID = 1
PROVIDER = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# INIT ########################################################################

forta_toolkit.logging.setup_logger(logging.INFO)
forta_toolkit.parsing.env.load_secrets()

def initialize():
    """Initialize the state variables that are tracked across tx and blocks."""
    global CHAIN_ID
    global PROVIDER
    CHAIN_ID = forta_toolkit.parsing.env.load_chain_id(provider=PROVIDER)
    return {}

# SCRAPING ####################################################################

get_code = functools.lru_cache(maxsize=2048)(PROVIDER.eth.get_code)

# SCANNER #####################################################################

def handle_transaction_factory(
    provider: Web3,
    min_confidence: float=src.options.MIN_CONFIDENCE,
    history_size: int=src.options.ALERT_HISTORY_SIZE
) -> callable:
    """Setup the main handler."""

    @forta_toolkit.profiling.timeit
    @forta_toolkit.alerts.alert_history(size=history_size)
    def __handle_transaction(log: TransactionEvent) -> list:
        """Main function called on the logs gathered by the Forta network."""
        global CHAIN_ID
        # result: list of alerts
        __findings = []
        # parse all the data
        __tx = forta_toolkit.parsing.transaction.parse_transaction_data(transaction=log.transaction)
        __logs = [forta_toolkit.parsing.logs.parse_log_data(log=__l) for __l in log.logs]
        __traces = [forta_toolkit.parsing.traces.parse_trace_data(trace=__t) for __t in log.traces]
        # iterate over event logs
        # for __l in __logs:
        #     # analyse the transaction
        #     __scores = src.scoring.score_log(log=__l)
        #     # iterate over the scan results
        #     for __id, __score in __scores.items():
        #         if __score >= min_confidence:
        #             # keep a trace on the node
        #             logging.info(src.findings.get_alert_description(chain_id=CHAIN_ID, alert_id=__id, transaction=__tx, log=__l, trace={}))
        #             # raise an alert
        #             __findings.append(src.findings.format_finding(chain_id=CHAIN_ID, alert_id=__id, confidence=__score, transaction=__tx, log=__l, trace={}))
        # iterate over each subtrace
        for __t in __traces:
            # analyse the transaction
            __scores = src.scoring.score_trace(trace=__t)
            # iterate over the scan results
            for __id, __score in __scores.items():
                if __score >= min_confidence:
                    # keep a trace on the node
                    logging.info(src.findings.get_alert_description(chain_id=CHAIN_ID, alert_id=__id, transaction=__tx, log={}, trace=__t))
                    # raise an alert
                    __findings.append(src.findings.format_finding(chain_id=CHAIN_ID, alert_id=__id, confidence=__score, transaction=__tx, log={}, trace=__t))
        return __findings

    return __handle_transaction

# MAIN ########################################################################

# run with the default settings
handle_transaction = handle_transaction_factory(provider=PROVIDER)

# TODO ########################################################################

# import forta_toolkit.parsing.transaction

# import ioseeth.metrics.evasion.morphing.logic_bomb
# import ioseeth.metrics.evasion.redirection

# is_hidden_proxy = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.redirection.is_hidden_proxy)
# is_red_pill = functools.lru_cache(maxsize=128)(ioseeth.metrics.evasion.morphing.logic_bomb.is_red_pill)

# def handle_transaction_factory(
#     provider: Web3,
#     min_confidence: float=src.options.MIN_CONFIDENCE,
#     history_size: int=src.options.ALERT_HISTORY_SIZE
# ) -> callable:
#     """Setup the main handler."""
#     @forta_toolkit.profiling.timeit
#     @forta_toolkit.alerts.alert_history(size=history_size)
#     def __handle_transaction(log: TransactionEvent) -> list:
#         """Main function called on the logs gathered by the Forta network."""
#         global CHAIN_ID
#         # result: list of alerts
#         __findings = []
#         __data = forta_toolkit.parsing.transaction.parse_transaction_data(transaction=log.transaction)
#         # analyse the transaction
#         __scores = score(**__data)
#         # metamorphic contracts
#         hidden proxy
#         if __scores['hidden-proxy'] >= min_confidence:
#             __findings.append(src.findings.FormatFindingHiddenProxy(
#                 chain=CHAIN_ID,
#                 txhash=log.transaction.hash,
#                 sender=__data['sender'],
#                 recipient=__data['recipient'],
#                 confidence=__scores['hidden-proxy']))
#         # red pill
#         if __scores['red-pill'] >= min_confidence:
#             __findings.append(src.findings.FormatFindingRedPill(
#                 chain=CHAIN_ID,
#                 txhash=log.transaction.hash,
#                 sender=__data['sender'],
#                 recipient=__data['recipient'],
#                 confidence=__scores['red-pill']))
#         return __findings
#     return __handle_transaction
