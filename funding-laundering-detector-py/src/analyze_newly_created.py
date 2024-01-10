from datetime import datetime, timedelta

from src.config import MIN_AGE_IN_DAYS

def is_newly_created(address, blockexplorer, timestamp):
    try:
        first_tx = blockexplorer.get_first_tx(address)

        tx_datetime = datetime.fromtimestamp(timestamp)

        if first_tx > tx_datetime - timedelta(days=MIN_AGE_IN_DAYS):
            return True
        else:
            return False
    except:
        return False
