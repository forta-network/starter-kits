from datetime import datetime, timedelta

from src.config import NEWLY_CREATED_MAX_TRANSACTIONS_AMOUNT, MIN_AGE_IN_DAYS

def is_newly_created(address, blockexplorer):
    try:
        first_tx = blockexplorer.get_first_tx(address)

        if first_tx > datetime.now() - timedelta(days=MIN_AGE_IN_DAYS):
            return True
        else:
            return False
    except:
        return False
