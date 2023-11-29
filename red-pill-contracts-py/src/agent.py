"""Forta agent scanning for batched transactions."""

import functools
import logging

from forta_agent import get_json_rpc_url
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import forta_toolkit.alerts
import forta_toolkit.logging
import forta_toolkit.parsing.env
import forta_toolkit.parsing.traces
import forta_toolkit.preprocessing
import forta_toolkit.profiling

import src.findings
import src.options
import src.scoring

# CONSTANTS ###################################################################

CHAIN_ID = 1
PROVIDER = Web3(Web3.HTTPProvider(get_json_rpc_url()))

# INIT ########################################################################

forta_toolkit.logging.setup_logger(level=logging.INFO, version=forta_toolkit.parsing.env.get_bot_version())

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
    global CHAIN_ID

    @forta_toolkit.profiling.timeit
    @forta_toolkit.alerts.alert_history(size=history_size)
    @forta_toolkit.preprocessing.parse_forta_arguments
    def __handle_transaction(transaction: dict, logs: list, traces: list, **kwargs) -> list:
        """Main function called on the logs gathered by the Forta network."""
        global CHAIN_ID
        # result: list of alerts
        __findings = []
        # iterate over each subtrace
        for __t in traces:
            # analyse the transaction
            __scores = src.scoring.score_trace(trace=__t)
            # iterate over the scan results
            for __id, __score in __scores.items():
                if __score >= min_confidence:
                    # keep a trace on the node
                    logging.info(src.findings.get_alert_description(chain_id=CHAIN_ID, alert_id=__id, transaction=transaction, log={}, trace=__t))
                    # raise an alert
                    __findings.append(src.findings.format_finding(chain_id=CHAIN_ID, alert_id=__id, confidence=__score, transaction=transaction, log={}, trace=__t))
        return __findings

    return __handle_transaction

# MAIN ########################################################################

# run with the default settings
handle_transaction = handle_transaction_factory(provider=PROVIDER)
