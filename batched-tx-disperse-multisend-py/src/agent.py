"""Forta agent scanning for batched transactions"""

from web3 import Web3
from forta_agent import get_json_rpc_url, Finding, FindingType, FindingSeverity

import src.constants as constants
import src.disperse as disperse
import src.findings as findings
import src.multisend as multisend

# CONSTANTS ###################################################################

ADDRESS_TO_NAME = {
    disperse.ADDRESS.lower(): 'Disperse',
    multisend.ADDRESS.lower(): 'Multisend'}

# SCANNER #####################################################################

def handle_transaction_factory(w3: Web3, token: str=constants.TOKEN):
    _parsers = {
        disperse.ADDRESS.lower(): disperse.parse_transaction_input_factory(w3=w3, token=token),
        multisend.ADDRESS.lower(): multisend.parse_transaction_input_factory(w3=w3, token=token)}

    def _handle_transaction(transaction_event):
        _findings = []
        _from = str(getattr(transaction_event.transaction, 'from_', '')).lower()
        _to = str(getattr(transaction_event.transaction, 'to', '')).lower() # could be None in case of a contract creation
        _data = str(getattr(transaction_event.transaction, 'data', '')).lower()
        _wrapped_tx = []
        
        if _to in _parsers:
            _wrapped_tx = _parsers[_to](_data)
            if _wrapped_tx:
                _findings.append(findings.FormatBatchTxFinding(
                    origin=_from,
                    contract=ADDRESS_TO_NAME[_to],
                    transactions=_wrapped_tx,
                    chain_id=w3.eth.chain_id))

        return _findings

    return _handle_transaction

handle_transaction = handle_transaction_factory(w3=Web3(Web3.HTTPProvider(get_json_rpc_url())))
