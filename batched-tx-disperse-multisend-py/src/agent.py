"""Forta agent scanning for batched transactions."""

from web3 import Web3
from forta_agent import get_json_rpc_url, FindingSeverity
from forta_agent.transaction_event import TransactionEvent

import src.metrics.batch as batch
import src.options as options
import src.findings as findings

# FILTERS #####################################################################

# PARSERS #####################################################################

def _parse(log: TransactionEvent, w3: Web3) -> dict:
    """Gather and parse the data from all the relevant sources in one dict."""
    _truc = {}
    _from = str(getattr(log.transaction, 'from_', '')).lower()
    _to = str(getattr(log.transaction, 'to', '')).lower() # could be None in case of a contract creation
    _data = str(getattr(log.transaction, 'data', '')).lower()
    return _truc

# SCANNER #####################################################################

def handle_transaction_factory(
    w3: Web3,
    target_token: str=options.TARGET_TOKEN,
    target_contract: str=options.TARGET_CONTRACT,
    min_transfer_count: int=options.MIN_TRANSFER_COUNT,
    min_transfer_total_erc20: int=options.MIN_TRANSFER_TOTAL_ERC20,
    min_transfer_total_native: int=options.MIN_TRANSFER_TOTAL_NATIVE,
    min_confidence_score: float=options.MIN_CONFIDENCE_SCORE,
    min_malicious_score: int=options.MIN_MALICIOUS_SCORE
) -> callable:
    """Setup the main"""
    _chain_id = w3.eth.chain_id

    def _handle_transaction(log: TransactionEvent) -> list:
        """Main function called on the logs gathered by the Forta network."""
        _findings = []
        print(batch.confidence_score(log=log, w3=w3))
        # _findings.append(findings.FormatBatchTxFinding(
        #     origin=_from,
        #     contract=ADDRESS_TO_NAME[_to],
        #     token=_token,
        #     transactions=_wrapped_tx,
        #     chain_id=_chain_id,
        #     severity=FindingSeverity.Low if _is_manual else FindingSeverity.Info))
        return _findings

    return _handle_transaction

# run with the default settings
handle_transaction = handle_transaction_factory(w3=Web3(Web3.HTTPProvider(get_json_rpc_url())))
