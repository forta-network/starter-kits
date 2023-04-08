from forta_agent import create_alert_event,FindingSeverity, AlertEvent, Label, EntityType
import agent
from datetime import datetime, timedelta

class TestMonitoringBot:

    def generate_alert(createAt: datetime, alert_hash = '0xabc') -> AlertEvent:
        # {
        #       "label": "Attacker",
        #       "confidence": 0.25,
        #       "entity": "0x2967E7Bb9DaA5711Ac332cAF874BD47ef99B3820",
        #       "entityType": "ADDRESS",
        #       "remove": false
        # },

        alert = {"alert":
                    {"name": "x",
                    "hash": alert_hash,
                    "addresses": [],
                    "description": f"0x2967E7Bb9DaA5711Ac332cAF874BD47ef99B3820 description",
                    "alertId": "SCAM-DETECTOR-1",
                    "createdAt": createAt.strftime("%Y-%m-%dT%H:%M:%S.%f123Z"),  # 2022-11-18T03:01:21.457234676Z
                    "source":
                        {"bot": {'id': "0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8"}, "block": {"chainId": 1, 'number': 5},  'transactionHash': '0x123'},
                    "metadata": {},
                    "labels": []
                    }
                }
        return create_alert_event(alert)
    
    def test_initialize(self):
        agent.initialize()



    def test_no_finding(self):
        agent.initialize()
        alert = TestMonitoringBot.generate_alert(datetime.now(), '0xabc')
        findings = agent.handle_alert(alert)
        assert len(findings) == 0

    def test_one_finding(self):
        start_time = agent.START_TIME
        agent.initialize()
        for i in range(1, 6):
            created_at = start_time + timedelta(hours=i)
            alert = TestMonitoringBot.generate_alert(created_at, '0xabc')
            findings = agent.handle_alert(alert)
            assert len(findings) == 0

        created_at = start_time + timedelta(hours=24)
        alert = TestMonitoringBot.generate_alert(created_at, '0xabc')
        findings = agent.handle_alert(alert)
        findings = agent.handle_alert(alert)
        findings = agent.handle_alert(alert)
        findings = agent.handle_alert(alert)
        
        next_hour = start_time + timedelta(hours=25)
        alert = TestMonitoringBot.generate_alert(next_hour, '0xabc')
        findings = agent.handle_alert(alert)
        assert len(findings) == 1
        assert findings[0].description == f'0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8, SCAM-DETECTOR-1, 1 alert rate outside of normal range at {created_at.replace(minute=0, second=0, microsecond=0)}.'
        assert findings[0].metadata['actual_value'] == 4
        assert findings[0].metadata['lower_bound'] < 0
        assert findings[0].metadata['lower_bound'] > -1
        assert findings[0].metadata['upper_bound'] > 0
        assert findings[0].metadata['upper_bound'] < 1
        assert findings[0].metadata['time_series_data'] == '1.0,1.0,1.0,1.0,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0'

