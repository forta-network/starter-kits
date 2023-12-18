import logging

import forta_agent
import rlp
import sys
import pandas as pd
from forta_agent import get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3
from os import environ

from src.constants import CONTRACT_QUEUE_SIZE
from src.findings import SocialEngContractFindings
from src.storage import get_secrets

SECRETS_JSON = get_secrets()

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

ALERTS_CACHE = set()

CONTRACTS_QUEUE = pd.DataFrame(columns=['contract_address', 'first_four_char', 'last_four_char'])

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

def initialize():
    """
    this function initializes the agent; only used for testing purposes to reset state across test cases

    """
    # global CONTRACTS_QUEUE
    # CONTRACTS_QUEUE = pd.DataFrame(columns={'contract_address', 'first_four_char', 'last_four_char'})

    global CHAIN_ID
    CHAIN_ID = web3.eth.chain_id

    global CONTRACTS_QUEUE
    CONTRACTS_QUEUE = pd.concat([CONTRACTS_QUEUE, pd.DataFrame({'contract_address': '0x0000000000000000000000000000000000000000', 'first_four_char': '0000', 'last_four_char': '0000'}, index=[len(CONTRACTS_QUEUE)])])

    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')


def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:]).lower()


def append_contract_finding(findings: list, created_contract_address: str, from_: str) -> None:
    """
        function assesses whether created contract address impersonates an existing contract
    """
    global CONTRACTS_QUEUE
    global ALERTS_CACHE
    logging.info("Contract created: " + created_contract_address)

    criteria1 = CONTRACTS_QUEUE["first_four_char"] == created_contract_address[2:6]
    criteria2 = CONTRACTS_QUEUE["last_four_char"] == created_contract_address[-4:]

    impersonated_contract_address = CONTRACTS_QUEUE[criteria1 & criteria2]["contract_address"]
    if len(impersonated_contract_address) > 0 and impersonated_contract_address.iloc[0] is not None and impersonated_contract_address.iloc[0] != created_contract_address and created_contract_address not in ALERTS_CACHE:
        if impersonated_contract_address.iloc[0] == '0x0000000000000000000000000000000000000000':
            findings.append(SocialEngContractFindings.social_eng_address_creation(created_contract_address, True, impersonated_contract_address.iloc[0], from_, CHAIN_ID, 'SOCIAL-ENG-CONTRACT-CREATION-NULL-ADDRESS'))
            ALERTS_CACHE.add(created_contract_address)
        else:
            findings.append(SocialEngContractFindings.social_eng_address_creation(created_contract_address, True, impersonated_contract_address.iloc[0], from_, CHAIN_ID, 'SOCIAL-ENG-CONTRACT-CREATION'))
            ALERTS_CACHE.add(created_contract_address)





def detect_social_eng_account_creations(w3, transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    global CONTRACTS_QUEUE
    global ALERTS_CACHE

    # contract creation - managing queue
    if transaction_event.to is not None:
        to = transaction_event.to.lower()
        if is_contract(w3, to):
            if len(CONTRACTS_QUEUE[CONTRACTS_QUEUE["contract_address"] == to]) == 0:
                logging.info("Adding contract to queue: " + to)
                logging.info("Contract size: " + str(len(CONTRACTS_QUEUE)))
                if not (to[2:6] == '0000' and to[-4:] == '0000'):
                    CONTRACTS_QUEUE = pd.concat([CONTRACTS_QUEUE, pd.DataFrame({'contract_address': to, 'first_four_char': to[2:6], 'last_four_char': to[-4:]}, index=[len(CONTRACTS_QUEUE)])])
            if len(CONTRACTS_QUEUE) > CONTRACT_QUEUE_SIZE:
                contract_to_remove = CONTRACTS_QUEUE.iloc[0]["contract_address"]
                logging.info("Removing contract to queue: " + contract_to_remove)
                CONTRACTS_QUEUE = CONTRACTS_QUEUE.drop(CONTRACTS_QUEUE.index[0])
                if contract_to_remove == '0x0000000000000000000000000000000000000000':
                    CONTRACTS_QUEUE = pd.concat([CONTRACTS_QUEUE, pd.DataFrame({'contract_address': '0x0000000000000000000000000000000000000000', 'first_four_char': '0000', 'last_four_char': '0000'}, index=[len(CONTRACTS_QUEUE)])])

    findings = []
    created_contract_addresses = []

    # contract creation - emit finding using non-trace contract creation flow
    if transaction_event.to is None:
        created_contract_address = calc_contract_address(w3, transaction_event.from_, transaction_event.transaction.nonce)
        append_contract_finding(findings, created_contract_address, transaction_event.from_)
    elif transaction_event.from_[2:6] == '0000' and transaction_event.from_[-4:] == '0000' and transaction_event.from_ != '0x0000000000000000000000000000000000000000': #only support null as the check would be too expensive at this point
        if transaction_event.from_ not in ALERTS_CACHE:
            findings.append(SocialEngContractFindings.social_eng_address_creation(transaction_event.from_, False, '0x0000000000000000000000000000000000000000', "", CHAIN_ID, 'SOCIAL-ENG-EOA-CREATION-NULL-ADDRESS'))
            ALERTS_CACHE.add(transaction_event.from_)


    # contract creation - emit finding using non-trace contract creation flow
    for trace in transaction_event.traces:
        if trace.type == 'create':
            if (transaction_event.from_ == trace.action.from_ or trace.action.from_ in created_contract_addresses):
                nonce = transaction_event.transaction.nonce if transaction_event.from_ == trace.action.from_ else 1  # for contracts creating other contracts, the nonce would be 1
                created_contract_address = calc_contract_address(w3, trace.action.from_, nonce)

                created_contract_addresses.append(created_contract_address.lower())
                append_contract_finding(findings, created_contract_address, transaction_event.from_)

    while len(ALERTS_CACHE) > 100000:
        ALERTS_CACHE.pop()

    return findings


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return detect_social_eng_account_creations(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)
