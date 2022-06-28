import time
from datetime import datetime, timedelta

import pandas as pd
from forta_agent import FindingSeverity, FindingType, create_block_event

import agent
from forta_explorer_mock import FortaExplorerMock
from web3_mock import Web3Mock

w3 = Web3Mock()


class TestAlertCombiner:

    def test_detect_alert_pos_finding(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        data = []
        start_date = datetime(2022, 4, 23, 10, 25, 55)
        end_date = datetime(2022, 4, 30, 10, 25, 55)  # block timestamp 1651314415
        current_date = start_date
        while current_date <= end_date:
            current_date += timedelta(minutes=5)
            for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        current_date -= timedelta(minutes=5)  # last row will be discarded as it could be incomplete; this row, we will create an anomalous count
        for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        df_forta = pd.DataFrame(data, columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        df_forta["createdAt"] = pd.to_datetime(df_forta["createdAt"], utc=True)

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"
        assert agent.FINDINGS_CACHE[0].type == FindingType.Suspicious, "this should have been a suspicious finding"
        assert agent.FINDINGS_CACHE[0].severity == FindingSeverity.High, "this should have been a high severity finding"
        assert agent.FINDINGS_CACHE[0].description == 'Upside breakout on bot 0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9, alert Reentrancy calls detected'
        assert agent.FINDINGS_CACHE[0].metadata["Observed_value"] == 20, "this should have been value of 20"
        assert agent.FINDINGS_CACHE[0].metadata["Range_boundary"] > 10, "this should have been value greater than 10"
        assert agent.FINDINGS_CACHE[0].metadata["Expected_value"] == 10, "this should have been 10"
        assert agent.FINDINGS_CACHE[0].metadata["Contract_address"] == "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "this should have been contract 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"

    def test_detect_alert_pos_finding_with_missing_values(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        data = []
        start_date = datetime(2022, 4, 23, 10, 25, 55)
        drop_start_date = datetime(2022, 4, 24, 10, 25, 55)
        drop_end_date = datetime(2022, 4, 25, 10, 25, 55)
        end_date = datetime(2022, 4, 30, 10, 25, 55)  # block timestamp 1651314415
        current_date = start_date
        while current_date <= end_date:
            current_date += timedelta(minutes=5)
            if current_date >= drop_start_date and current_date <= drop_end_date:
                continue
            for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        current_date -= timedelta(minutes=5)  # last row will be discarded as it could be incomplete; this row, we will create an anomalous count
        for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        df_forta = pd.DataFrame(data, columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        df_forta["createdAt"] = pd.to_datetime(df_forta["createdAt"], utc=True)

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"
        assert agent.FINDINGS_CACHE[0].type == FindingType.Suspicious, "this should have been a suspicious finding"
        assert agent.FINDINGS_CACHE[0].severity == FindingSeverity.High, "this should have been a high severity finding"
        assert agent.FINDINGS_CACHE[0].description == 'Upside breakout on bot 0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9, alert Reentrancy calls detected'
        assert agent.FINDINGS_CACHE[0].metadata["Observed_value"] == 20, "this should have been value of 20"
        assert agent.FINDINGS_CACHE[0].metadata["Range_boundary"] > 10, "this should have been value greater than 10"
        assert agent.FINDINGS_CACHE[0].metadata["Expected_value"] == 10, "this should have been 10"
        assert agent.FINDINGS_CACHE[0].metadata["Contract_address"] == "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "this should have been contract 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"

    def test_detect_alert_pos_no_repeat_finding(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        data = []
        start_date = datetime(2022, 4, 23, 10, 25, 55)
        end_date = datetime(2022, 4, 30, 10, 25, 55)  # block timestamp 1651314415
        current_date = start_date
        while current_date <= end_date:
            current_date += timedelta(minutes=5)
            for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        current_date -= timedelta(minutes=5)  # last row will be discarded as it could be incomplete; this row, we will create an anomalous count
        for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        df_forta = pd.DataFrame(data, columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        df_forta["createdAt"] = pd.to_datetime(df_forta["createdAt"], utc=True)

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"
        agent.FINDINGS_CACHE = []

        agent.detect_attack(w3, forta_explorer, block_event)
        time.sleep(1)
        assert len(agent.FINDINGS_CACHE) == 0, "this should have have triggered another finding"

    def test_detect_alert_pos_nofinding(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        data = []
        start_date = datetime(2022, 4, 23, 10, 25, 55)
        end_date = datetime(2022, 4, 30, 10, 25, 55)  # block timestamp 1651314415
        current_date = start_date
        while current_date <= end_date:
            current_date += timedelta(minutes=5)
            for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        df_forta = pd.DataFrame(data, columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        df_forta["createdAt"] = pd.to_datetime(df_forta["createdAt"], utc=True)

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 0, "this should not have triggered a finding"

    def test_detect_alert_no_data_nofinding(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        data = []
        df_forta = pd.DataFrame(data, columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        df_forta["createdAt"] = pd.to_datetime(df_forta["createdAt"], utc=True)

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 0, "this should not have triggered a finding"

    def test_detect_alert_pos_finding_incomplete_time_series(self):
        agent.initialize()

        forta_explorer = FortaExplorerMock()

        data = []
        start_date = datetime(2022, 4, 29, 10, 25, 55)
        end_date = datetime(2022, 4, 30, 10, 25, 55)  # block timestamp 1651314415
        current_date = start_date
        while current_date <= end_date:
            current_date += timedelta(minutes=5)
            for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        current_date -= timedelta(minutes=5)  # last row will be discarded as it could be incomplete; this row, we will create an anomalous count
        for i in range(10):
                data.append([current_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "Reentrancy calls detected", "ethereum",
                    "SUSPICIOUS", {"transactionHash": "0x53244cc27feed6c1d7f44381119cf14054ef2aa6ea7fbec5af4e4258a5a02617", "block": {"number": 15004290, "chainId": 1}, "bot": {"id": "0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9"}},
                    "HIGH", {}, "NETHFORTA-25", "description", ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"], [], "0x32abd26df70f12b4d2527a092b8f42a467dd6356fcff57a0d9241ac1c6244e10"])

        df_forta = pd.DataFrame(data, columns=['createdAt', 'name', 'protocol', 'findingType', 'source', 'severity', 'metadata', 'alertId', 'description', 'addresses', 'contracts', 'hash'])

        df_forta["createdAt"] = pd.to_datetime(df_forta["createdAt"], utc=True)

        forta_explorer.set_df(df_forta)
        block_event = create_block_event({
            'block': {
                'timestamp': 1651314415,
            }
        })

        agent.detect_attack(w3, forta_explorer, block_event)

        time.sleep(1)

        assert len(agent.FINDINGS_CACHE) == 1, "this should have triggered a finding"
        assert agent.FINDINGS_CACHE[0].type == FindingType.Suspicious, "this should have been a suspicious finding"
        assert agent.FINDINGS_CACHE[0].severity == FindingSeverity.High, "this should have been a high severity finding"
        assert agent.FINDINGS_CACHE[0].description == 'Upside breakout on bot 0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9, alert Reentrancy calls detected'
        assert agent.FINDINGS_CACHE[0].metadata["Observed_value"] == 20, "this should have been value of 20"
        assert agent.FINDINGS_CACHE[0].metadata["Range_boundary"] > 10, "this should have been value greater than 10"
        assert agent.FINDINGS_CACHE[0].metadata["Expected_value"] == 10, "this should have been 10"
        assert agent.FINDINGS_CACHE[0].metadata["Contract_address"] == "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "this should have been contract 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
