import logging
import sys
from datetime import datetime, timedelta

import forta_agent
import networkx as nx
import rlp
import requests
from forta_agent import Finding, FindingSeverity, FindingType, get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3
import pickle
import os

from dotenv import load_dotenv
load_dotenv()

from src.constants import MAX_AGE_IN_DAYS, MAX_NONCE, ALERTED_ADDRESSES_KEY, FINDINGS_CACHE_KEY, GRAPH_KEY

web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

FINDINGS_CACHE = []
ALERTED_ADDRESSES = []
GRAPH = nx.DiGraph()

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

DATABASE = "https://research.forta.network/database/bot/"
ERC20_TRANSFER_EVENT = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'


def initialize():
    """
    this function initializes the state variables that are tracked across tx and blocks
    it is called from test to reset state between tests
    """
    global ALERTED_ADDRESSES
    alerted_address = load(ALERTED_ADDRESSES_KEY)
    ALERTED_ADDRESSES = [] if alerted_address is None else list(alerted_address)

    global FINDINGS_CACHE
    findings_cache = load(FINDINGS_CACHE_KEY)
    FINDINGS_CACHE = [] if findings_cache is None else findings_cache

    global GRAPH
    graph = load(GRAPH_KEY)
    GRAPH = nx.DiGraph() if graph is None else nx.DiGraph(graph)



def persist(obj: object, key: str):
    if os.environ.get('LOCAL_NODE') is None:
        logging.info(f"Persisting {key} using API")
        bytes = pickle.dumps(obj)
        token = forta_agent.fetch_jwt({})

        headers = {"Authorization": f"Bearer {token}"}
        res = requests.post(f"{DATABASE}{key}", data=bytes, headers=headers)
        logging.info(f"Persisting {key} to database. Response: {res}")
        return
    else:
        logging.info(f"Persisting {key} locally")
        pickle.dump(obj, open(key, "wb"))


def load(key: str) -> object:
    if os.environ.get('LOCAL_NODE') is None:
        logging.info(f"Loading {key} using API")
        token = forta_agent.fetch_jwt({})
        logging.info("Fetched token")
        logging.info(token)
        headers = {"Authorization": f"Bearer {token}"}
        res = requests.get(f"{DATABASE}{key}", headers=headers)
        logging.info(f"Loaded {key}. Response: {res}")
        if res.status_code==200 and len(res.content) > 0:
            return pickle.loads(res.content)
        else:
            logging.info(f"{key} does not exist")
    else:
        # load locally
        logging.info(f"Loading {key} locally")
        if os.path.exists(key):
            return pickle.load(open(key, "rb"))
        else:
            logging.info(f"File {key} does not exist")
    return None


def add_address(w3, address):
    global GRAPH

    if address is None:
        return

    if "00000000" in address:
        return

    checksum_address = Web3.toChecksumAddress(address)
    if w3.eth.get_transaction_count(checksum_address) <= MAX_NONCE:
        if checksum_address in GRAPH.nodes:
            GRAPH.nodes[checksum_address]["last_seen"] = datetime.now()
            logging.info(f"Updated address {checksum_address} last_seen in graph. Graph size is still {len(GRAPH.nodes)}")
        else:
            GRAPH.add_node(checksum_address, last_seen=datetime.now())
            logging.info(f"Added address {checksum_address} to graph. Graph size is now {len(GRAPH.nodes)}")


def prune_graph():
    global GRAPH

    #  looks at each node in the graph and assesses how old it is
    #  if its older than MAX_AGE_IN_DAYS, it will be removed from the graph
    #  note, if the nonce is larger than MAX_NONCE, it will not be removed from the graph 
    #  as the nonce is only assessed when the node is created

    nodes_to_remove = set()
    for node in GRAPH.nodes:
        if datetime.now() - GRAPH.nodes[node]["last_seen"] > timedelta(days=MAX_AGE_IN_DAYS):
            nodes_to_remove.add(node)

    for node in nodes_to_remove:
        GRAPH.remove_node(node)
        logging.info(f"Removed address {node} from graph. Graph size is now {len(GRAPH.nodes)}")


def add_directed_edge(w3, from_, to):
    global GRAPH

    if from_ is None or to is None:
        return

    if Web3.toChecksumAddress(from_) in GRAPH.nodes and Web3.toChecksumAddress(to) in GRAPH.nodes:
        GRAPH.add_edges_from([(Web3.toChecksumAddress(from_), Web3.toChecksumAddress(to))])
        logging.info(f"Added edge from address {from_} to {to}.")
        

def calc_contract_address(w3, address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:]).lower()


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes('0x')


def cluster_entities(w3, transaction_event) -> list:
    findings = []
    
    add_address(w3, transaction_event.transaction.from_)
    add_address(w3, transaction_event.transaction.to)

    #  add contract node if it is a contract creation transaction
    if transaction_event.transaction.to is None:
        contract_address = calc_contract_address(w3, transaction_event.transaction.from_, transaction_event.transaction.nonce)
        add_address(w3, contract_address)

    prune_graph()

    #  add edges for each native transfer
    if transaction_event.transaction.value > 0:
        logging.info(f"Observing native transfer of value {transaction_event.transaction.value} from {transaction_event.transaction.from_} to {transaction_event.transaction.to}")
        if not is_contract(w3, transaction_event.transaction.to) and not is_contract(w3, transaction_event.transaction.from_):
            add_directed_edge(w3, transaction_event.transaction.from_, transaction_event.transaction.to)
            print("0")
            finding = create_finding(transaction_event.transaction.from_)
            if finding is not None:
                findings.append(finding)

    #  add edges for ERC20 transfers
    transfer_events = transaction_event.filter_log(ERC20_TRANSFER_EVENT)
    for transfer_event in transfer_events:
        # extract transfer event arguments
        if transfer_event['args']['value'] > 0:
            logging.info(f"Observing ERC-20 transfer of value {transfer_event['args']['value']} from {transfer_event['args']['from']} to {transfer_event['args']['to']}")
            if not is_contract(w3, transfer_event['args']['to']) and not is_contract(w3, transfer_event['args']['from']):
                add_directed_edge(w3, transfer_event['args']['from'], transfer_event['args']['to'])
                finding = create_finding(transfer_event['args']['from'])
                if finding is not None:
                    findings.append(finding)

    # add edges for contract creations
    if transaction_event.transaction.to is None:
        logging.info(f"Observing contract creation from {transaction_event.transaction.from_}: {contract_address}")
        contract_address = calc_contract_address(w3, transaction_event.transaction.from_, transaction_event.transaction.nonce)
        add_directed_edge(w3, transaction_event.transaction.from_, contract_address)
        add_directed_edge(w3, contract_address, transaction_event.transaction.from_)
        finding = create_finding(transaction_event.transaction.from_)
        if finding is not None:
            findings.append(finding)

    return findings


def filter_edge(n1, n2):
    # filters for bidirectional edges
    if [n2, n1] in GRAPH.edges:
        return True
    return False


def create_finding(from_) -> Finding:
    filtered_graph = nx.subgraph_view(GRAPH, filter_edge=filter_edge)
    undirected_graph = filtered_graph.to_undirected()
    
    #  find all connected components
    connected_components = list(nx.connected_components(undirected_graph))

    #  find the connected component that contains the from_ address
    for component in connected_components:
        if Web3.toChecksumAddress(from_) in component and len(component) > 1:
            if component not in FINDINGS_CACHE:
                FINDINGS_CACHE.append(component)

                if len(FINDINGS_CACHE) > 10000:
                    FINDINGS_CACHE.pop(0)

                return Finding(
                    {
                        "name": "Entity identified",
                        "description": f"Entity of size {len(component)} has been identified. Transaction from {from_} created this entity.",
                        "alert_id": "ENTITY-CLUSTER",
                        "type": FindingType.Info,
                        "severity": FindingSeverity.Info,
                        "metadata": {
                            "entity_addresses": list(component)
                        }
                    }
                )
            

def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return cluster_entities(w3, transaction_event)

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)

def persist_state():
    global GRAPH
    global ALERTED_ADDRESSES
    global FINDINGS_CACHE

    persist(GRAPH, GRAPH_KEY)
    persist(FINDINGS_CACHE, FINDINGS_CACHE_KEY)
    persist(ALERTED_ADDRESSES, ALERTED_ADDRESSES_KEY)
    logging.info(f"Persisted bot state.")

def handle_block(block_event: forta_agent.block_event.BlockEvent) -> list:
    logging.info(f"Handling block {block_event.block_number}.")

    persist_state()

    findings = []
    return findings

def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
    return real_handle_transaction(transaction_event)