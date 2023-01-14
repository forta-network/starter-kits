from blockexplorer import BlockExplorer
from datetime import datetime, timedelta


class TestBlockExplorer:
    def test_get_first_tx(self):
        first_tx = BlockExplorer(1).get_first_tx("0x690B9A9E9aa1C9dB991C7721a92d351Db4FaC990")
        assert first_tx < datetime.now() - timedelta(days=55), "first_tx is too low"