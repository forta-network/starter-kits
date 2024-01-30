from typing import Callable
from ..utils import assert_exists
from ..common import ScanAlertsOptions
from ..handlers import RunHandlersOnAlert

RunAlert = Callable[[str, ScanAlertsOptions], None]

def provide_run_alert(run_handlers_on_alert: RunHandlersOnAlert):
  assert_exists(run_handlers_on_alert, 'run_handlers_on_alert')

  async def run_alert(alert_hash: str, options: ScanAlertsOptions) -> None:
    alert_hashes = [alert_hash]
    # support for specifying multiple alerts with comma-delimited list
    if alert_hash.find(",") >= 0:
      alert_hashes = alert_hash.split(",")

    for hash in alert_hashes:
      await run_handlers_on_alert(hash, options)

  return run_alert