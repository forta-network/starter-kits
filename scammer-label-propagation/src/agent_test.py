import time
from forta_agent import  create_alert_event, create_block_event
import agent
import json
import unittest
from constants import N_WORKERS


class TestScammerLabelPropagationAgent(unittest.TestCase):
    def test_initialize(self):
        subscription_json = agent.initialize()
        json.dumps(subscription_json)
        assert True, "initialize() should return a valid JSON"
    
    def test_process_event_alert_without_label(self):
        agent.initialize()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "alert",
                 "source":
                    {"bot": {'id': "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"}},
                 "labels": []
                 }
             })
        _ = agent.handle_alert(alert)
        assert len(agent.global_futures) == 0, "handle_alert() should not add any address to the pool if there is no label"

    def test_process_event_alert_under_threshold(self):
        agent.initialize()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "alert",
                 "source":
                    {"bot": {'id': "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"}},
                 "labels": [{
                        'entity': '0xfb4c68caccfa3ea46a7d9a7b59a3f91b40705194',
                        'label': 'Attacker',
                        'confidence': 0.1,
                        'entity_type': 'Address'
                    }]
                 }
             })
        _ = agent.handle_alert(alert)
        assert len(agent.global_futures) == 0, "handle_alert() should not add any address to the pool if confidence is under threshold"
    
    def test_process_event_alert_over_threshold(self):
        agent.initialize()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "alert",
                 "source":
                    {"bot": {'id': "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"}},
                 "labels": [{
                        'entity': '0xfb4c68caccfa3ea46a7d9a7b59a3f91b40705194',
                        'label': 'Attacker',
                        'confidence': 1,
                        'entity_type': 'Address'
                    }]
                 }
             })
        _ = agent.handle_alert(alert)
        assert len(agent.global_futures) == 1, "handle_alert() should add the address to the pool if confidence is over threshold"
        block_event = create_block_event(
            {'block': {'hash': '0xa', 'number': 1}})
        while len(agent.global_futures) > 0:
            time.sleep(30)
            findings = agent.handle_block(block_event)
        assert len(findings) >= 1, "handle_block() should return multiple findings"
        assert len(agent.global_futures) == 0, "handle_block() should remove the address from the pool"


    def test_event_with_multiple_alerts(self):
        agent.initialize()
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "alert",
                 "source":
                    {"bot": {'id': "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"}},
                 "labels": [{
                        'entity': '0xfb4c68caccfa3ea46a7d9a7b59a3f91b40705194',
                        'label': 'Attacker',
                        'confidence': 1,
                        'entity_type': 'Address'
                    },
                    {
                        'entity': '0x6e01af3913026660fcebb93f054345eccd972251',
                        'label': 'Attacker',
                        'confidence': 1,
                        'entity_type': 'Address'
                    }]
                 }
             })
        _ = agent.handle_alert(alert)
        assert len(agent.global_futures) == 2, "handle_alert() should add the all labels to the pool"
        block_event = create_block_event(
            {'block': {'hash': '0xa', 'number': 1}})
        findings = []
        while len(agent.global_futures) > 0:
            time.sleep(30)
            findings += agent.handle_block(block_event)
        assert len(findings) >= 1, "handle_block() should return multiple findings"


    def test_repeated_address(self):
        """
        This test works with the dynamo table. In the real world, the multiple instances will be in different nodes, but here
        we force it by having the same alert multiple times. The expected result is that it will add the address to the pool
        up to three times, and then stop adding it
        """
        central_node = '0xfb4c68caccfa3ea46a7d9a7b59a3f91b40705194'
        alert = create_alert_event(
            {"alert":
                {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "alert",
                 "source":
                    {"bot": {'id': "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"}},
                 "labels": [{
                        'entity': central_node,
                        'label': 'Attacker',
                        'confidence': 1,
                        'entity_type': 'Address'
                    }]
                 }
             })
        agent.initialize()
        n_times_dynamodb = agent.get_address_from_dynamo(central_node)
        while n_times_dynamodb < 4:
            agent.initialize()
            assert len(agent.global_futures) == 0, "handle_alert() should not have anything running after initialization"
            _ = agent.handle_alert(alert)
            if n_times_dynamodb < 3:
                assert len(agent.global_futures) == 1, "handle_alert() should add the address to the pool"
                n_times_dynamodb = agent.get_address_from_dynamo(central_node)
            else:
                assert len(agent.global_futures) == 0, "handle_alert() should not add the address to the pool"
                n_times_dynamodb += 1        

    def test_more_addresses_than_concurrency(self):
        central_nodes = [
            '0xab01b6fa35daf2d2c6467669ff64a8cc95692514', '0x39e5efbf80a074cd0656599753b04ee616b15d7b',
            '0x41473c5ecde5cfedb9c8ff1e339f985a61f38eee', '0x063a2953fb36cc8ebeac80259dd8a1c972ad778a',
            '0x6e01af3913026660fcebb93f054345eccd972251',
            '0x5b4ae7d49421705882e999a75ecdfdfe17da7878', '0xe464da92a137365e0bab6b7b122465a36310bfb3'
        ]
        agent.initialize()
        alert = {"alert":
                 {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alertId": "alert",
                 "source":
                    {"bot": {'id': "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"}},
                 "labels": [{
                        'entity': 'asdf',
                        'label': 'Attacker',
                        'confidence': 1,
                        'entity_type': 'Address'
                    }]
                 }
             }
        for node in central_nodes:
            alert['alert']['labels'][0]['entity'] = node
            _ = agent.handle_alert(create_alert_event(alert))
        assert len(agent.global_futures) == 7, "handle_alert() should add the addresses to the pool"
        currently_running = 0
        for _, future in agent.global_futures.items():
            if future.running():
                currently_running += 1
        # 
        assert currently_running <= N_WORKERS, "The number of concurrent processes should be less than the maximum number of workers"
        findings = []
        block_event = create_block_event(
            {'block': {'hash': '0xa', 'number': 1}})
        while len(agent.global_futures) > 0:
            time.sleep(30)
            findings += agent.handle_block(block_event)
    
    def test_run_all_extended(self):
        central_node = '0xfa080f371f2b9986dfd0a692da4da343178233d0'
        alert = {"alert":
                 {"name": "x",
                 "hash": "0xabc",
                 "description": "description",
                 "alert_id": "alert",
                 "source":
                    {"bot": {'id': "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"}},
                 "labels": [{
                        'entity': central_node,
                        'label': 'Attacker',
                        'confidence': 1,
                        'entity_type': 'Address'
                    }]
                 }
             }
        agent.run_all_extended(central_node, create_alert_event(alert))



if __name__ == '__main__':
    unittest.main()
