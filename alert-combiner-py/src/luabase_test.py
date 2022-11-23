from datetime import datetime, timedelta
from luabase import Luabase


class TestLuabase:
    def test_execute_query(self):
        start_date = datetime.now() - timedelta(days=1)

        df = Luabase().execute_query(f"select count() from ethereum.transactions where CAST(block_timestamp as date) >= '{start_date.strftime('%Y-%m-%d')}'")
        assert len(df) > 0, "no transactions returned"

    def test_get_denominator(self):
        start_date = datetime.now() - timedelta(days=1)
        end_date = datetime.now()

        tx_count = Luabase().get_denominator("tx-count", start_date, end_date)
        assert tx_count > 0, "no transactions returned"
