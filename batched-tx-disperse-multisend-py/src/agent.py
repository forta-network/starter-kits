"""Forta agent scanning for batched transactions."""

from itertools import chain
from pprint import pprint

from forta_agent import get_json_rpc_url, FindingSeverity
from forta_agent.transaction_event import TransactionEvent
from web3 import Web3

import src._balances as balances
import src._chains as chains
import src._events as events
import src._inputs as inputs
import src.metrics.airdrop as airdrop
import src.metrics.batch as batch
import src.metrics.erc20 as erc20
import src.metrics.native as native
import src.metrics.nft as nft
import src.options as options
import src.findings as findings

# FILTERS #####################################################################

# PARSERS #####################################################################

def _parse(log: TransactionEvent, w3: Web3) -> dict:
    """Gather and parse the data from all the relevant sources in one dict."""
    _from = str(getattr(log.transaction, 'from_', '')).lower()
    _to = str(getattr(log.transaction, 'to', '')).lower()
    _data = str(getattr(log.transaction, 'data', '')).lower()
    _metadata = {
        'scores': {
            'batch': (batch.confidence_score(log=log, w3=w3), batch.malicious_score(log=log, w3=w3)),},
        'from': _from,
        'to': _to, # could be None in case of a contract creation
        'data': _data,
        'balance_updates': '',
        'erc20_events': '',
        'erc721_events': ''}
    return _metadata

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
    """Setup the main handler."""
    _chain_id = int(w3.eth.chain_id)

    def _handle_transaction(log: TransactionEvent) -> list:
        """Main function called on the logs gathered by the Forta network."""
        _findings = []
        _token = ''
        _transfers = []
        # parse the log
        _data = str(getattr(log.transaction, 'data', '')).lower()
        _block = int(log.block.number)
        # analyse the transaction
        _batch_score = batch.confidence_score(log=log, w3=w3)
        _airdrop_score = airdrop.confidence_score(log=log, w3=w3)
        _erc20_score = erc20.confidence_score(log=log, w3=w3)
        _nft_score = nft.confidence_score(log=log, w3=w3)
        _native_score = 0.
        # raise an alert
        if _batch_score >= 0.6:
            if _erc20_score >= 0.6:
                _token = 'ERC20'
                _transfers = events.parse_log(log=log, abi=events.ERC20_TRANSFER_EVENT)
            elif _nft_score >= 0.6:
                _token = 'ERC721'
                _transfers = events.parse_log(log=log, abi=events.ERC721_TRANSFER_EVENT)
            else:
                _native_score = native.confidence_score(log=log, w3=w3)
                if _native_score >= 0.6:
                    _token = chains.CURRENCIES.get(_chain_id, 'ETH')
                    _recipients = chain.from_iterable(inputs.get_array_of_address_candidates(data=_data, min_length=min_transfer_count))
                    _transfers = [balances.get_balance_delta(w3=w3, address=_r, block=_block) for _r in _recipients]
            pprint({
                'confidence': _batch_score,
                'token': _token,
                'transfers': _transfers}) # native.confidence_score(log=log, w3=w3)
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
