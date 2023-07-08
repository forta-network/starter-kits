from agent import EntityClusterAgent
from forta_agent import create_transaction_event
from datetime import datetime, timedelta
import time
import networkx as nx

from web3 import Web3
from web3_mock import CONTRACT, EOA_ADDRESS_LARGE_TX, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD, EOA_ADDRESS_SMALL_TX, EOA_ADDRESS_FUNDED_NEW, EOA_ADDRESS_FUNDED_OLD, EOA_ADDRESS_FUNDER_NEW, EOA_ADDRESS_FUNDER_OLD, Web3Mock
from constants import ALERTED_ADDRESSES_KEY, GRAPH_KEY
from forta_agent import get_alerts, get_json_rpc_url
import timeit

w3 = Web3Mock()
real_w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
from persistance import DynamoPersistance


class TestEntityClusterBot:

    def remove_persistent_state():
        test_util_persistance = DynamoPersistance()
        test_util_persistance.clean_db()

    def test_prune_graph_age(self):
        #  create a graph with some addresses which are older and newer than MAX_AGE_IN_DAYS
        #  assert that the old ones are removed and the new ones are not
        entity_cluster_agent = EntityClusterAgent(DynamoPersistance())

        entity_cluster_agent.add_address(EOA_ADDRESS_NEW)
        entity_cluster_agent.add_address(EOA_ADDRESS_OLD)

        entity_cluster_agent.GRAPH.nodes[EOA_ADDRESS_NEW]["last_seen"] = datetime.now() - timedelta(days=6)
        entity_cluster_agent.GRAPH.nodes[EOA_ADDRESS_OLD]["last_seen"] = datetime.now() - timedelta(days=8)
        
        EntityClusterAgent.prune_graph(entity_cluster_agent.GRAPH)

        assert len(entity_cluster_agent.GRAPH.nodes) == 1, "Old address was not removed from graph"

    def test_add_address_discard(self):
        #  calls address on address with too large of a nonce
        agent = EntityClusterAgent(DynamoPersistance())
        if agent.is_address_belong_max_transactions(w3, EOA_ADDRESS_LARGE_TX):
            agent.add_address(EOA_ADDRESS_LARGE_TX)

        assert len(agent.GRAPH.nodes) == 0, "Address shouldnt have been added to graph. Its nonce is too large"

    def test_add_address_valid(self):
        #  calls address on address with appropriate nonce
        agent = EntityClusterAgent(DynamoPersistance())
        if agent.is_address_belong_max_transactions(w3, EOA_ADDRESS_SMALL_TX):
            agent.add_address(EOA_ADDRESS_SMALL_TX)

        assert len(agent.GRAPH.nodes) == 1, "Address should have been added to graph. Its nonce is within range"

    def test_persist(self):
        TestEntityClusterBot.remove_persistent_state()
        agent = EntityClusterAgent(DynamoPersistance())

        agent.add_address(EOA_ADDRESS_SMALL_TX)
        agent.persist_state()  # will perist state

        assert len(agent.GRAPH.nodes) == 1, "Address should have been added to graph. Its nonce is within range"


    def test_add_directed_edges_without_add(self):
        agent = EntityClusterAgent(DynamoPersistance())

        agent.add_directed_edge(w3, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD)

        assert len(agent.GRAPH.nodes) == 0, "No addresses were added initially, so should be empty"

    def test_add_directed_edges_with_add(self):
        agent = EntityClusterAgent(DynamoPersistance())

        agent.add_address(EOA_ADDRESS_NEW)
        agent.add_address(EOA_ADDRESS_OLD)
        agent.add_directed_edge(w3, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD)

        assert len(agent.GRAPH.nodes) == 2, "Addresses were added initially"
        assert len(agent.GRAPH.edges) == 1, "Edge should exist"

    def test_filter_edge(self):
        agent = EntityClusterAgent(DynamoPersistance())

        agent.add_address(EOA_ADDRESS_NEW)
        agent.add_address(EOA_ADDRESS_OLD)
        agent.add_directed_edge(w3, EOA_ADDRESS_NEW, EOA_ADDRESS_OLD)

        filtered_graph = nx.subgraph_view(agent.GRAPH, filter_edge=EntityClusterAgent.filter_edge(agent.GRAPH))
        assert len(filtered_graph.edges) == 0, "Edge should have been filtered out"

        agent.add_directed_edge(w3, EOA_ADDRESS_OLD, EOA_ADDRESS_NEW)
        filtered_graph = nx.subgraph_view(agent.GRAPH, filter_edge=EntityClusterAgent.filter_edge(agent.GRAPH))
        assert len(filtered_graph.edges) == 2, "Edges should not have been filtered out"

    def test_finding_bidirectional(self):
        TestEntityClusterBot.remove_persistent_state()
        agent = EntityClusterAgent(DynamoPersistance())

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
        agent = EntityClusterAgent(DynamoPersistance())

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
        agent = EntityClusterAgent(DynamoPersistance())

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
        agent = EntityClusterAgent(DynamoPersistance())

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
        agent = EntityClusterAgent(DynamoPersistance())

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
        agent = EntityClusterAgent(DynamoPersistance())

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

    def test_entity_cluster_perf_test(self):
        TestEntityClusterBot.remove_persistent_state()
        global real_w3
        global transf_token_appproval
        approver_address = '0xE262C8471ec5fB9f59BE38a657d9c04dDe065BC3'
        erc20_contract = '0x409B46013C78C63cf376f17466aeF87895617451'
        transf_token_appproval = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': approver_address,
                'to': erc20_contract,
                'value': 0,
                'nonce': 8,

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })

        smallTxSender = '0xf7f2bf2b45422c0887215bf654b86ce4ddd86b29'
        smallTxReceiver = '0x634d1ca25f5a0a20b7273ca92a8fd5318d3c5f74'
        global small_transfer
        small_transfer = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': smallTxSender,
                'to': smallTxReceiver,
                'value': 10000000

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })


        contract_creator = '0x6e3D99E288Ad0a4A1F8eE0F25e0Ef31F20b78360'
        global contract_creation
        contract_creation = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': contract_creator,
                'to': None,
                'value': 0,
                'nonce': 1

            },
            'block': {
                'number': 0,
                'timestamp': datetime.now().timestamp(),
            },
            'receipt': {
                'logs': []}
        })


        #bidirectional transfer
        eoa_bi_tx_left = '0x36D11536dD7C4073031dE2D039A5C3c78B3243C0'
        eoa_bi_tx_right = '0x4789FDB2B8C9a7FBB26CF0a54a33f06d0cd658A8'
        global native_transfer_bidirectional_right
        native_transfer_bidirectional_right = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': eoa_bi_tx_left,
                    'to': eoa_bi_tx_right,
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
        
        global native_transfer_bidirectional_left
        native_transfer_bidirectional_left = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': eoa_bi_tx_right,
                    'to': eoa_bi_tx_left,
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
        


        #One directional big transfer
        global one_directional_big_transfer
        one_directional_big_transfer = create_transaction_event({

            'transaction': {
                'hash': "0",
                'from': '0x9F6f4B51361394e69a18922B59e92b30DA026F8a',
                'to': '0xc10CD0e22f6a543cBED8fe8F94D1B1B484Db7EDF',
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


        # Chain: Blocktime, Number of Tx -> Avg processing time in ms target
        # Ethereum(1): 12s, 150 -> 80ms
        # BSC(56): 3s, 70 -> 43ms
        # Polygon(137): 2s, 50 -> 40ms
        # Avalanche: 2s, 5 -> 400ms
        # Arbitrum(42161): 1s, 5 -> 200ms
        # Optimism(10): 24s, 150 -> 160ms
        # Fantom(250): 1s, 5 -> 200ms

        # local testing reveals an avg processing time of 1480, which results in the following sharding config:
        # Ethereum: 12s, 150 -> 80ms - 15
        # BSC: 3s, 70 -> 43ms - ?
        # Polygon: 2s, 50 -> 40ms - ?
        # Avalanche: 2s, 5 -> 400ms - ?
        # Arbitrum: 1s, 5 -> 200ms - ?
        # Optimism: 24s, 150 -> 160ms - ?
        # Fantom: 1s, 5 -> 200ms - ?
        
        
        
        processing_runs = 1
        processing_time_normal_contract_itearation_like_ERC30_approve = 0
        processing_time_small_transaction_with_finding = 0
        processing_time_bi_directional_tx_right = 0
        processing_time_bi_directional_tx_left_with_finding = 0
        processing_time_one_directional_big_transfer = 0
        processing_time_contract_creation_transaction = 0
        processing_time_ERC20_bi_directional_tx_right = 0
        processing_time_ERC20_bi_directional_tx_left_with_finding = 0 
        for i in range(processing_runs):
            TestEntityClusterBot.remove_persistent_state()
            global agent
            agent = EntityClusterAgent(DynamoPersistance())
            processing_time_normal_contract_itearation_like_ERC30_approve += timeit.timeit('agent.cluster_entities(real_w3, transf_token_appproval)', number=processing_runs, globals=globals()) * 1000 
            processing_time_small_transaction_with_finding += timeit.timeit('agent.cluster_entities(real_w3, small_transfer)', number=processing_runs, globals=globals()) * 1000 

            processing_time_bi_directional_tx_right += timeit.timeit('agent.cluster_entities(real_w3, native_transfer_bidirectional_right)', number=processing_runs, globals=globals()) * 1000 
            processing_time_bi_directional_tx_left_with_finding += timeit.timeit('agent.cluster_entities(real_w3, native_transfer_bidirectional_left)', number=processing_runs, globals=globals()) * 1000 

            processing_time_one_directional_big_transfer += timeit.timeit('agent.cluster_entities(real_w3, one_directional_big_transfer)', number=processing_runs, globals=globals()) * 1000 


            # Trying several times with the python profiler
            processing_time_contract_creation_transaction += 3025

            #we asume the a ERC20 transfer will take the same as bi directional transfer plus 10ms for parsing the events
            processing_time_ERC20_bi_directional_tx_right += processing_time_bi_directional_tx_right + 10
            processing_time_ERC20_bi_directional_tx_left_with_finding += processing_time_bi_directional_tx_left_with_finding + 10

        avg_processing_time_normal_contract_itearation_like_ERC30_approve = processing_time_normal_contract_itearation_like_ERC30_approve / processing_runs
        avg_processing_time_small_transaction_with_finding = processing_time_small_transaction_with_finding / processing_runs
        avg_processing_time_bi_directional_tx_right = processing_time_bi_directional_tx_right / processing_runs
        avg_processing_time_bi_directional_tx_left_with_finding = processing_time_bi_directional_tx_left_with_finding / processing_runs
        avg_processing_time_one_directional_big_transfer = processing_time_one_directional_big_transfer / processing_runs
        avg_processing_time_contract_creation_transaction =  processing_time_contract_creation_transaction / processing_runs
        avg_processing_time_ERC20_bi_directional_tx_right = processing_time_ERC20_bi_directional_tx_right / processing_runs
        avg_processing_time_ERC20_bi_directional_tx_left_with_finding = processing_time_ERC20_bi_directional_tx_left_with_finding / processing_runs
        

        avg_tx_time = (avg_processing_time_normal_contract_itearation_like_ERC30_approve 
                + avg_processing_time_small_transaction_with_finding 
                + avg_processing_time_bi_directional_tx_right 
                + avg_processing_time_bi_directional_tx_left_with_finding 
                + avg_processing_time_one_directional_big_transfer 
                + avg_processing_time_contract_creation_transaction 
                + avg_processing_time_ERC20_bi_directional_tx_right 
                + avg_processing_time_ERC20_bi_directional_tx_left_with_finding ) / 8

        avg_tx_time_weight = avg_processing_time_normal_contract_itearation_like_ERC30_approve * 0.5 \
                       + avg_processing_time_small_transaction_with_finding * 0.11 \
                       + avg_processing_time_bi_directional_tx_right * 0.10 \
                       + avg_processing_time_bi_directional_tx_left_with_finding * 0.03\
                       + avg_processing_time_one_directional_big_transfer * 0.08 \
                       + avg_processing_time_contract_creation_transaction * 0.05 \
                       + avg_processing_time_ERC20_bi_directional_tx_right * 0.10 \
                       + avg_processing_time_ERC20_bi_directional_tx_left_with_finding * 0.03


        print("avg_tx_time " + str(avg_tx_time))
        print("avg_tx_time_weight " + str(avg_tx_time_weight))



       
        assert avg_tx_time_weight < 1900, f"processing should be greater less"


    def test_shard_subgraph_poc (self):
        #bi directional
        G = nx.DiGraph()
        H = nx.DiGraph()
        address1 = "A"
        address2 = "B"
        G.add_node(address1, last_seen=datetime.now())
        H.add_node(address2, last_seen=datetime.now())

        G.add_edges_from([(address1, address2)])
        H.add_edges_from([(address2, address1)])

        F = nx.compose(G,H)

        filtered_graph = nx.subgraph_view(F, filter_edge= EntityClusterAgent.filter_edge(F))
        undirected_graph = filtered_graph.to_undirected()

        #  find all connected components
        connected_components = list(nx.connected_components(undirected_graph))
        assert {address1, address2} in connected_components



    def test_shrading_finding_bidirectional_in_redundacy_env(self):
        TestEntityClusterBot.remove_persistent_state()

        right_addr = '0x05f75788d3ec37bc8357c9ba88054c1650dd31f5'
        left_addr = '0xB0e5DDCBAA6c3524896767872797091F04aD0e19'


        

        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': left_addr,
                    'to': right_addr,
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
        
        agent1b = EntityClusterAgent(DynamoPersistance())   
        agent1b.cluster_entities(real_w3, native_transfer1)
        agent1a = EntityClusterAgent(DynamoPersistance())
        findings = agent1a.cluster_entities(real_w3, native_transfer1)
        assert len(findings) == 0, "No findings should be returned as it is not bidirectional"

        native_transfer2 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': right_addr,
                    'to': left_addr,
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
        
        agent2b = EntityClusterAgent(DynamoPersistance())
        agent2b.cluster_entities(real_w3, native_transfer2)
        agent2a = EntityClusterAgent(DynamoPersistance())
        findings = agent2a.cluster_entities(real_w3, native_transfer2)
        assert len(findings) == 1, "Finding should be returned as it is bidirectional"


    def test_shrading_finding_bidirectional(self):
        TestEntityClusterBot.remove_persistent_state()

        right_addr = '0x05f75788d3ec37bc8357c9ba88054c1650dd31f5'
        left_addr = '0xB0e5DDCBAA6c3524896767872797091F04aD0e19'
    
        agent1 = EntityClusterAgent(DynamoPersistance())


        native_transfer1 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': right_addr,
                    'to': left_addr,
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

        findings = agent1.cluster_entities(real_w3, native_transfer1)
        assert len(findings) == 0, "No findings should be returned as it is not bidirectional"
        native_transfer2 = create_transaction_event({

                'transaction': {
                    'hash': "0",
                    'from': left_addr,
                    'to': right_addr,
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
        
        agent2 = EntityClusterAgent(DynamoPersistance())

        findings = agent2.cluster_entities(real_w3, native_transfer2)
        assert len(findings) == 1, "Finding should be returned as it is bidirectional"