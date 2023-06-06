import pandas as pd
from datetime import datetime

from forta_explorer import FortaExplorer
from web3_mock import EOA_ADDRESS_SMALL_TX


class TestFortaExplorer:
    def test_query_label(self):
        #entity: str, source_id: str, start_date: datetime, end_date: datetime
        labels = FortaExplorer.get_labels("0x3184fd21cc2d2e89704ae2d214ad76f22b0591a4","0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23", datetime(2023,6,1),datetime(2023,6,6))
        assert labels is not None
        assert len(labels) > 0
        assert "scammer-eoa" in labels.iloc[0].labelstr
        assert "SCAM-DETECTOR-ADDRESS-POISONING" in labels.iloc[0].alertId
        assert 1 == labels.iloc[0].chainId
        