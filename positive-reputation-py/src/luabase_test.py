from datetime import datetime, timedelta
from luabase import Luabase


class TestLuabase:
    def test_execute_query(self):
        start_date = datetime.now() - timedelta(days=1)

        df = Luabase().execute_query(f"select count() from ethereum.transactions where CAST(block_timestamp as date) >= '{start_date.strftime('%Y-%m-%d')}'")
        assert len(df) > 0, "no transactions returned"

    def test_first_tx(self):
        first_tx = Luabase().get_first_tx("0x690B9A9E9aa1C9dB991C7721a92d351Db4FaC990")
        assert first_tx < datetime.now() - timedelta(days=55), "first_tx is too low"
