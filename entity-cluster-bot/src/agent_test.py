import agent
from forta_agent import create_transaction_event
from datetime import datetime, timedelta
import os
import networkx as nx

from web3 import Web3
from web3_mock import CONTRACT, EOA_ADDRESS_LARGE_TX, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD, EOA_ADDRESS_SMALL_TX, EOA_ADDRESS_FUNDED_NEW, EOA_ADDRESS_FUNDED_OLD, EOA_ADDRESS_FUNDER_NEW, EOA_ADDRESS_FUNDER_OLD, Web3Mock
from constants import ALERTED_ADDRESSES_KEY, FINDINGS_CACHE_KEY, GRAPH_KEY
from forta_agent import get_alerts
w3 = Web3Mock()

class TestEntityClusterBot:

    def remove_persistent_state():
        if os.path.isfile(ALERTED_ADDRESSES_KEY):
            os.remove(ALERTED_ADDRESSES_KEY)
        if os.path.isfile(FINDINGS_CACHE_KEY):
            os.remove(FINDINGS_CACHE_KEY)
        if os.path.isfile(GRAPH_KEY):
            os.remove(GRAPH_KEY)
    

    def test_prune_graph_age(self):
        #  create a graph with some addresses which are older and newer than MAX_AGE_IN_DAYS
        #  assert that the old ones are removed and the new ones are not
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        agent.add_address(w3, EOA_ADDRESS_NEW)
        agent.add_address(w3, EOA_ADDRESS_OLD)

        agent.GRAPH.nodes[EOA_ADDRESS_NEW]["last_seen"] = datetime.now() - timedelta(days=6)
        agent.GRAPH.nodes[EOA_ADDRESS_OLD]["last_seen"] = datetime.now() - timedelta(days=8)
        
        agent.prune_graph()

        assert len(agent.GRAPH.nodes) == 1, "Old address was not removed from graph"

    def test_add_address_discard(self):
        #  calls address on address with too large of a nonce
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        agent.add_address(w3, EOA_ADDRESS_LARGE_TX)

        assert len(agent.GRAPH.nodes) == 0, "Address shouldnt have been added to graph. Its nonce is too large"

    def test_add_address_valid(self):
        #  calls address on address with appropriate nonce
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        agent.add_address(w3, EOA_ADDRESS_SMALL_TX)

        assert len(agent.GRAPH.nodes) == 1, "Address should have been added to graph. Its nonce is within range"

    def test_persist(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        agent.add_address(w3, EOA_ADDRESS_SMALL_TX)
        agent.persist_state()  # will perist state

        agent.initialize()  # will load state
        assert len(agent.GRAPH.nodes) == 1, "Address should have been added to graph. Its nonce is within range"


    def test_add_directed_edges_without_add(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        agent.add_directed_edge(w3, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD)

        assert len(agent.GRAPH.nodes) == 0, "No addresses were added initially, so should be empty"

    def test_add_directed_edges_with_add(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        agent.add_address(w3, EOA_ADDRESS_NEW)
        agent.add_address(w3, EOA_ADDRESS_OLD)
        agent.add_directed_edge(w3, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD)

        assert len(agent.GRAPH.nodes) == 2, "Addresses were added initially"
        assert len(agent.GRAPH.edges) == 1, "Edge should exist"

    def test_filter_edge(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        agent.add_address(w3, EOA_ADDRESS_NEW)
        agent.add_address(w3, EOA_ADDRESS_OLD)
        agent.add_directed_edge(w3, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD)

        filtered_graph = nx.subgraph_view(agent.GRAPH, filter_edge=agent.filter_edge)
        assert len(filtered_graph.edges) == 0, "Edge should have been filtered out"

        agent.add_directed_edge(w3, EOA_ADDRESS_OLD, EOA_ADDRESS_NEW)
        filtered_graph = nx.subgraph_view(agent.GRAPH, filter_edge=agent.filter_edge)
        assert len(filtered_graph.edges) == 2, "Edges should not have been filtered out"

    def test_finding_bidirectional(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS_NEW,
                    'to': EOA_ADDRESS_OLD,
                    'value': 1000000000000000000,
                    'nonce': 8,

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

        findings = agent.cluster_entities(w3, native_transfer1)
        assert len(findings) == 0, "No findings should be returned as it is not bidirectional"

        native_transfer2 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS_OLD,
                    'to': EOA_ADDRESS_NEW,
                    'value': 1000000000000000000,
                    'nonce': 8,

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

        findings = agent.cluster_entities(w3, native_transfer2)
        assert len(findings) == 1, "Finding should be returned as it is bidirectional"

    def test_nofinding_onedirectional_below_threshold(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS_NEW,
                    'to': EOA_ADDRESS_OLD,
                    'value': 40000000000000000000,
                    'nonce': 8,

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

        findings = agent.cluster_entities(w3, native_transfer1)
        assert len(findings) == 0, "No findings should be returned as it is below eth threshold"

    def test_finding_onedirectional_above_threshold(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS_NEW,
                    'to': EOA_ADDRESS_OLD,
                    'value': 60000000000000000000,
                    'nonce': 8,

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

        findings = agent.cluster_entities(w3, native_transfer1)
        assert len(findings) == 1, "Findings should be returned as it is above eth threshold even though its onedirectional"

    def test_finding_onedirectional_initial_funds_new_account(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS_FUNDER_NEW,
                    'to': EOA_ADDRESS_FUNDED_NEW,
                    'value': 10000000

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

        findings = agent.cluster_entities(w3, native_transfer1)
        assert len(findings) == 1, "Findings should be returned as it is new account transfer"

    def test_finding_onedirectional_initial_funds_new_account_above_threshold(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS_FUNDER_NEW,
                    'to': EOA_ADDRESS_FUNDED_NEW,
                    'value': 1000000000000000000

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

        findings = agent.cluster_entities(w3, native_transfer1)
        assert len(findings) == 0, "Findings should not be returned as it is new account transfer, but too much value"

    def test_finding_onedirectional_initial_funds_old_account(self):
        TestEntityClusterBot.remove_persistent_state()
        agent.initialize()

        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': EOA_ADDRESS_FUNDER_NEW,
                    'to': EOA_ADDRESS_FUNDED_OLD,
                    'value': 100000000

                },
                'block': {
                    'number': 0,
                    'timestamp': datetime.now().timestamp(),
                },
                'receipt': {
                    'logs': []}
            })

        findings = agent.cluster_entities(w3, native_transfer1)
        assert len(findings) == 0, "No findings should be returned as it old account transfer"


