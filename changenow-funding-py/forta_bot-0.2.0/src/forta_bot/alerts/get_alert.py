from typing import Callable
from datetime import datetime
from ..utils import assert_exists
from .alert import Alert
from .get_alerts import GetAlerts

GetAlert = Callable[[str], Alert]

LOOKBACK_PERIOD_DAYS = 90
ONE_DAY_IN_SECONDS = 86400

def provide_get_alert(get_alerts: GetAlerts) -> GetAlert:
  assert_exists(get_alerts, 'get_alerts')

  async def get_alert(alert_hash: str) -> Alert:
    # TODO check cache

    # fetch the alert
    end_date = int(datetime.now().timestamp())
    start_date = end_date - (LOOKBACK_PERIOD_DAYS * ONE_DAY_IN_SECONDS)
    response = await get_alerts({
      'alert_hash': alert_hash,
      'block_date_range': {
        'start_date': datetime.fromtimestamp(start_date),
        'end_date': datetime.fromtimestamp(end_date)
      }
    })
    if len(response.alerts) == 0:
      raise Exception(f'no alert found with hash {alert_hash}')
    
    alert = response.alerts[0]
    # TODO write to cache
    return alert
  
  return get_alert