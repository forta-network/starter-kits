from forta_explorer import FortaExplorer
from datetime import datetime, timedelta


class TestFortaExplorer:
    def test_empty_alerts(self):
        df = FortaExplorer().empty_alerts()
        assert len(df) == 0, "empty alerts should be empty"

    def test_alerts_by_bot(self):
        start_date = datetime.now()
        end_date = start_date + timedelta(days=1)

        df = FortaExplorer().alerts_by_bot("0x492c05269cbefe3a1686b999912db1fb5a39ce2e4578ac3951b0542440f435d9", "Reentrancy calls detected", "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", start_date, end_date)  # uniswap reentrancy; triggers a lot
        assert len(df) > 0, "no alerts returned"

        alerts = df["alertId"].unique()
        assert len(alerts) > 0, "no alerts returned"
