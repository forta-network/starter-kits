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
        chain_id = 1

        tx_count = Luabase().get_denominator(chain_id, "tx-count", start_date, end_date)
        assert tx_count > 0, "no transactions returned"

    def test_get_alert_count(self):
        start_date = datetime.now() - timedelta(days=1)
        end_date = datetime.now()
        chain_id = 1
        bot_id = '0x0ffe038c802784f739bb27fcd4274f71c384fea78de87c9ef8d5b3fb72b514c7'
        alert_id = 'IMPOSSIBLE-2'

        tx_count = Luabase().get_alert_count(chain_id, bot_id, alert_id, start_date, end_date)
        assert tx_count > 0, "no transactions returned"
