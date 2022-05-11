from forta_explorer import FortaExplorer
from datetime import datetime, timedelta


class TestFortaExplorer:
    def test_empty_alerts(self):
        df = FortaExplorer().empty_alerts()
        assert len(df) == 0, "empty alerts should be empty"

    def test_alerts_by_agent(self):
        start_date = datetime.now()
        end_date = start_date + timedelta(days=1)

        df = FortaExplorer().alerts_by_agent("0x457aa09ca38d60410c8ffa1761f535f23959195a56c9b82e0207801e86b34d99", start_date, end_date)
        assert len(df) > 0, "no alerts returned"

        alerts = df["alertId"].unique()
        assert len(alerts) > 0, "no alerts returned"
