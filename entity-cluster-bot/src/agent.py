import logging
import sys
from datetime import datetime, timedelta
import json
import base64
import forta_agent
import networkx as nx
import rlp
from forta_agent import Finding, FindingSeverity, FindingType, get_json_rpc_url
from hexbytes import HexBytes
from web3 import Web3
from bot_alert_rate import calculate_alert_rate, ScanCountType
import cProfile
import pstats
from os import environ

from dotenv import load_dotenv
load_dotenv()

try:
    from src.constants import (
        MAX_AGE_IN_DAYS,
        MAX_NONCE,
        GRAPH_KEY,
        ONE_WAY_WEI_TRANSFER_THRESHOLD,
        NEW_FUNDED_MAX_WEI_TRANSFER_THRESHOLD,
        NEW_FUNDED_MAX_NONCE,
        TX_SAVE_STEP,
        HTTP_RPC_TIMEOUT,
        PROFILING,
        BOT_ID,
        PROD_TAG,
        SEVERITY_ALERT_FILTER,
        MALICIOUS_SMART_CONTRACT_BOT_ID,
        CLUSTER_SENDER,
    )
    from src.persistance import DynamoPersistance
    from src.storage import get_secrets
except ModuleNotFoundError:
    from constants import (
        MAX_AGE_IN_DAYS,
        MAX_NONCE,
        GRAPH_KEY,
        ONE_WAY_WEI_TRANSFER_THRESHOLD,
        NEW_FUNDED_MAX_WEI_TRANSFER_THRESHOLD,
        NEW_FUNDED_MAX_NONCE,
        TX_SAVE_STEP,
        HTTP_RPC_TIMEOUT,
        PROFILING,
        BOT_ID,
        PROD_TAG,
    )
    from persistance import DynamoPersistance
    from storage import get_secrets



SECRETS_JSON = get_secrets()
ZETTABLOCK_KEY = SECRETS_JSON['apiKeys']['ZETTABLOCK']


web3 = Web3(Web3.HTTPProvider(get_json_rpc_url(), request_kwargs={'timeout': HTTP_RPC_TIMEOUT}))

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(BOTNAME)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

ERC20_TRANSFER_EVENT = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}'

class ContextFilter(logging.Filter):
    def filter(self, record):
        record.BOTNAME = 'unknown'
        return True
handler.addFilter(ContextFilter())

class EntityClusterAgent:

    GRAPH = nx.DiGraph()
    persistance: DynamoPersistance = None
    tx_counter = 0
    tx_save_step = 1
    contract_cache =[]
    previous_shared_graphs = []
    chain_id = None


    def __init__(self, a_persistance: DynamoPersistance, tx_save_step = 1, chain_id = 1):
        self.persistance = a_persistance
        class ContextFilter(logging.Filter):
            def filter(self, record):
                if a_persistance.name:
                    record.BOTNAME = a_persistance.name
                else:
                    record.BOTNAME = 'unknown'
                return True
        handler.addFilter(ContextFilter())
        self.chain_id = chain_id
        logging.info(f"Run initialize chain: {self.chain_id}")
        self.tx_save_step = tx_save_step
        self.GRAPH = nx.DiGraph()
        environ["ZETTABLOCK_API_KEY"] = ZETTABLOCK_KEY



    def load(self, key: str) -> object:
        return self.persistance.load(key)

    def add_address(self, address):
        if address is None:
            return

        if "00000000" in address:
            return

        checksum_address = Web3.toChecksumAddress(address)
        if checksum_address in self.GRAPH.nodes:
            self.GRAPH.nodes[checksum_address]["last_seen"] = datetime.now()
            logging.info(f"Updated address {checksum_address} last_seen in graph. Graph size is still {len(self.GRAPH.nodes)}")
        else:
            self.GRAPH.add_node(checksum_address, last_seen=datetime.now())
            logging.info(f"Added address {checksum_address} to graph. Graph size is now {len(self.GRAPH.nodes)}")

    def is_address_below_max_transactions(self, w3, address):
        if address is None:
            return False

        if "00000000" in address:
            return False

        checksum_address = Web3.toChecksumAddress(address)
        return w3.eth.get_transaction_count(checksum_address) <= MAX_NONCE

    def prune_graph(a_graph):
        #  looks at each node in the graph and assesses how old it is
        #  if its older than MAX_AGE_IN_DAYS, it will be removed from the graph
        #  note, if the nonce is larger than MAX_NONCE, it will not be removed from the graph
        #  as the nonce is only assessed when the node is created

        nodes_to_remove = set()
        for node in a_graph.nodes:
            if datetime.now() - a_graph.nodes[node]["last_seen"] > timedelta(days=MAX_AGE_IN_DAYS):
                nodes_to_remove.add(node)

        for node in nodes_to_remove:
            a_graph.remove_node(node)
            logging.info(f"Removed address {node} from graph. Graph size is now {len(a_graph.nodes)}")


    def add_directed_edge(self, w3, from_, to):

        if from_ is None or to is None:
            return

        if Web3.toChecksumAddress(from_) in self.GRAPH.nodes and Web3.toChecksumAddress(to) in self.GRAPH.nodes:
            self.GRAPH.add_edges_from([(Web3.toChecksumAddress(from_), Web3.toChecksumAddress(to))])
            logging.info(f"Added edge from address {from_} to {to}.")


    def calc_contract_address(self, address, nonce) -> str:
        """
        this function calculates the contract address from sender/nonce
        :return: contract address: str
        """

        address_bytes = bytes.fromhex(address[2:].lower())
        return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:]).lower()


    def is_contract(self, w3, address) -> bool:
        """
        this function determines whether address is a contract
        :return: is_contract: bool
        """
        if address is None:
            return True

        checksum_address = Web3.toChecksumAddress(address)
        if checksum_address in self.contract_cache:
            logging.info(f"Using cache for is contract for contract {checksum_address}")
            return True
        code = w3.eth.get_code(checksum_address)
        if code != HexBytes('0x'):
            self.contract_cache.append(checksum_address)
            if len(self.contract_cache) > 10000:
                self.contract_cache.pop(0)
            return True
        else:
            return False


    def cluster_entities(self, w3, transaction_event) -> list:
        findings = []
        if (transaction_event.transaction.to is None) or (transaction_event.transaction.value > 0) or (transaction_event.filter_log(ERC20_TRANSFER_EVENT)):

            EntityClusterAgent.prune_graph(self.GRAPH)

            #  add edges for each native transfer, treated as bidirectional if sender and recipient nonces are less than or equal to NEW_FUNDED_MAX_NONCE _OR_ if large native transfer
            if transaction_event.transaction.value > 0:
                if not self.is_contract(w3, transaction_event.transaction.to) and not self.is_contract(w3, transaction_event.transaction.from_):
                        if self.is_address_below_max_transactions(w3, transaction_event.transaction.from_) and self.is_address_below_max_transactions(w3, transaction_event.transaction.to):
                            self.add_address(transaction_event.transaction.from_)
                            self.add_address(transaction_event.transaction.to)
                            self.add_directed_edge(w3, transaction_event.transaction.from_, transaction_event.transaction.to)
                            if (w3.eth.get_transaction_count(Web3.toChecksumAddress(transaction_event.transaction.from_), transaction_event.block.number) <= NEW_FUNDED_MAX_NONCE and w3.eth.get_transaction_count(Web3.toChecksumAddress(transaction_event.transaction.to), transaction_event.block.number) <= NEW_FUNDED_MAX_NONCE) or transaction_event.transaction.value > ONE_WAY_WEI_TRANSFER_THRESHOLD:
                                self.add_directed_edge(w3, transaction_event.transaction.to, transaction_event.transaction.from_)
                                if transaction_event.transaction.value < NEW_FUNDED_MAX_WEI_TRANSFER_THRESHOLD:
                                    logging.info(f"Observing small native transfer of value {transaction_event.transaction.value} from new EOA {transaction_event.transaction.from_} to new EOA {transaction_event.transaction.to}")
                                    finding = self.create_finding(transaction_event.transaction.from_, "Trigger by a small transfer to new accounts")
                                elif transaction_event.transaction.value > ONE_WAY_WEI_TRANSFER_THRESHOLD:
                                    logging.info(f"Observing large native transfer of value {transaction_event.transaction.value} from {transaction_event.transaction.from_} to {transaction_event.transaction.to}")
                                    finding = self.create_finding(transaction_event.transaction.from_, "Trigger by a large native transaction")
                                else:
                                    logging.info(f"Observing native transfer of value {transaction_event.transaction.value} from {transaction_event.transaction.from_} to {transaction_event.transaction.to}")
                                    finding = self.create_finding(transaction_event.transaction.from_, "Trigger by a bi directional transfer")
                            else:
                                logging.info(f"Observing native transfer of value {transaction_event.transaction.value} from {transaction_event.transaction.from_} to {transaction_event.transaction.to}")
                                finding = self.create_finding(transaction_event.transaction.from_, "Trigger by a bi directional transfer")
                            if finding is not None:
                                findings.append(finding)

            #  add edges for ERC20 transfers
            transfer_events = transaction_event.filter_log(ERC20_TRANSFER_EVENT)
            for transfer_event in transfer_events:
                # extract transfer event arguments
                if transfer_event['args']['value'] > 0:
                    erc20_from = transfer_event['args']['from']
                    erc20_to = transfer_event['args']['to']
                    logging.info(f"Observing ERC-20 transfer of value {transfer_event['args']['value']} from {erc20_from} to {erc20_to}")
                    if not self.is_contract(w3, erc20_to) and not self.is_contract(w3, erc20_from):
                        if self.is_address_below_max_transactions(w3, erc20_to) and self.is_address_below_max_transactions(w3, erc20_from):
                            self.add_address(erc20_from)
                            self.add_address(erc20_to)
                            self.add_directed_edge(w3, erc20_from, erc20_to)
                            finding = self.create_finding(erc20_from, "triger by bi directional ERC20 transfer")
                            if finding is not None:
                                findings.append(finding)

            # add edges for contract creations
            if transaction_event.transaction.to is None:
                contract_address = self.calc_contract_address(transaction_event.transaction.from_, transaction_event.transaction.nonce)
                logging.info(f"Observing contract creation from {transaction_event.transaction.from_}: {contract_address}")
                if self.is_address_below_max_transactions(w3, transaction_event.transaction.from_):
                    self.add_address(transaction_event.transaction.from_)
                    self.add_address(contract_address)
                    self.add_directed_edge(w3, transaction_event.transaction.from_, contract_address)
                    self.add_directed_edge(w3, contract_address, transaction_event.transaction.from_)
                    finding = self.create_finding(transaction_event.transaction.from_, "Trigger by a contract creation")
                    if finding is not None:
                        findings.append(finding)

            self.tx_counter = self.tx_counter + 1
            if self.tx_counter >= self.tx_save_step:
                self.persist_state()
                self.tx_counter = 0
                logging.info(f"Persist at {self.tx_save_step} tx")

        return findings


    def filter_edge(a_graph):
        def f(n1, n2):
            # filters for bidirectional edges
            if [n2, n1] in a_graph.edges:
                return True
            return False
        return f

    def create_finding(self, from_, message) -> Finding:
        shared_graph = self.persistance.graph_cache
        # Add all nodes and all edges to the shared cached graph to have a updated graph with the delta + shared
        shared_graph.update(self.GRAPH)
        filtered_graph = nx.subgraph_view(shared_graph, filter_edge=EntityClusterAgent.filter_edge(shared_graph))
        checksum_addr = Web3.toChecksumAddress(from_)

        ############################################
        # Uncomment to view graph in cytoscape viewer
        ##########################################
        # ego_g = nx.ego_graph(filtered_graph, Web3.toChecksumAddress("0xc7081c60da6eb75e6f2a4a55c33580f0fee8d7da"), 100)
        # c=0
        # for node in ego_g:
        #     ego_g.nodes[node]['last_seen'] = str(ego_g.nodes[node]['last_seen'])
        #     c=c+1
        # print(f"graph n {c}")
        # nx.write_graphml(ego_g, f"cytoscape.xml")


        # uses ego graph where the from address is the ego node and look for all his alters up to level 100
        # https://networkx.org/documentation/stable/auto_examples/drawing/plot_ego_graph.html


        ego_g = nx.ego_graph(filtered_graph, Web3.toChecksumAddress(checksum_addr), 100)
        nodes = list(ego_g.nodes)
        n_nodes = len(nodes)

        diagram = "Too big or small for a diagram"
        if 8 <= n_nodes and n_nodes <= 16:
            try:
                ego_for_json = ego_g.copy()
                for n in ego_for_json:
                    ego_for_json.nodes[n]["name"] = n
                    ego_for_json.nodes[n]['last_seen'] = str(ego_for_json.nodes[n]['last_seen'])
                link_data = nx.json_graph.node_link_data(ego_for_json)
                diagram = base64.b64encode(json.dumps(link_data).encode()).decode()
            except Exception as e:
                diagram = f"There was an error creating the diagram: {e}"

        alert_id = 'ENTITY-CLUSTER'
        anomality_score = 0
        if self.chain_id not in [43114, 10, 250]:
            try:
                anomality_score = calculate_alert_rate(
                                    self.chain_id,
                                    BOT_ID,
                                    alert_id,
                                    ScanCountType.TRANSFER_COUNT,
                                )
            except Exception as e:
                logging.error(f"Error doing calculate_alert_rate  {e}, default to {anomality_score}")

        #  find the connected component that contains the from_ address
        if checksum_addr in nodes and n_nodes > 1:
            return Finding(
                {
                    "name": "Entity identified",
                    "description": f"Entity of size {n_nodes} has been identified. Transaction from {from_} created this entity. {message}",
                    "alert_id": alert_id,
                    "type": FindingType.Info,
                    "severity": FindingSeverity.Info,
                    "metadata": {
                        "entity_addresses": nodes,
                        "diagram": diagram,
                        "anomaly_score": anomality_score
                    }
                }
            )



    def provide_handle_transaction(self, w3, transaction_event):
        # to save stats of a transaction processing, can be seen with viewers that help a lot to see where the time is being spent.
        if PROFILING:
            with cProfile.Profile() as profile:
                f = self.cluster_entities(w3, transaction_event)

            with open('profiling_stats.txt', 'w') as stream:
                stats = pstats.Stats(profile, stream=stream)
                stats.strip_dirs()
                stats.sort_stats('time')
                stats.dump_stats('entity_cluster_prof_stats')
                stats.print_stats()
            return f
        else:
            return self.cluster_entities(w3, transaction_event)


    def real_handle_transaction(self, transaction_event):
        return self.provide_handle_transaction(web3, transaction_event)

    def persist_state(self):
        self.persistance.persist(self.GRAPH, GRAPH_KEY, EntityClusterAgent.prune_graph)


    def provide_handle_alert(self, alert_event: forta_agent.alert_event.AlertEvent, cluster_sender=CLUSTER_SENDER):
        logging.debug("provide_handle_alert called")

        if alert_event.chain_id != self.chain_id:
            logging.debug("Alert not processed because it is not from the same chain")
        else:
            if alert_event.bot_id != MALICIOUS_SMART_CONTRACT_BOT_ID:
                logging.debug(
                    f"Alert not processed not monitoring that bot {alert_event.bot_id} - alert id : {alert_event.alert.alert_id} - chain id {self.chain_id}"
                )
            else:
                if alert_event.alert.severity != SEVERITY_ALERT_FILTER:
                    logging.debug(
                        f"Alert not processed not monitoring that severity {alert_event.alert.severity} - alert id : {alert_event.alert.alert_id} - chain id {self.chain_id}"
                    )
                else:
                    logging.debug(
                        f"Processing alert {alert_event.alert.alert_id} - chain id {self.chain_id} - bot id {alert_event.bot_id} - severity {alert_event.alert.severity}"
                    )
                    return self.process_alert(alert_event, cluster_sender=cluster_sender)
        return []

    def process_alert(self, alert_event: forta_agent.alert_event.AlertEvent, cluster_sender=CLUSTER_SENDER):
        findings = []
        finding = None
        description = alert_event.alert.description
        if "created contract" in description:
            description_split = description.split(" ")
            creator_address = description_split[0]
            contract_address = description_split[-1]
            self.add_address(contract_address)
            self.add_address(creator_address)
            self.add_directed_edge(web3, creator_address, contract_address)
            self.add_directed_edge(web3, contract_address, creator_address) #fake bidirectionnal edge to prevent filtering
            finding = self.create_finding(
                creator_address, "Triggered by high risk contract creation"
            )
            if finding is not None:
                findings.append(finding)
                finding = None

        if cluster_sender:
            transaction = web3.eth.get_transaction(
                alert_event.transaction_hash
            )
            sender_address = transaction["from"]
            if str.lower(sender_address) != str.lower(creator_address):
                self.add_address(sender_address)
                self.add_directed_edge(web3, sender_address, creator_address)
                self.add_directed_edge(web3, creator_address, sender_address)
                finding = self.create_finding(
                    sender_address, "Triggered by high risk contract creation, transaction sender"
                )
            if finding is not None:
                findings.append(finding)
            

        return findings


entity_cluster_agent = EntityClusterAgent(
    DynamoPersistance(PROD_TAG, web3.eth.chain_id), TX_SAVE_STEP, web3.eth.chain_id
)


def handle_transaction(
    transaction_event: forta_agent.transaction_event.TransactionEvent,
) -> list:
    return entity_cluster_agent.real_handle_transaction(transaction_event)


def handle_alert(alert_event: forta_agent.alert_event.AlertEvent):
    logging.debug("handle_alert called")

    return entity_cluster_agent.provide_handle_alert(alert_event)
