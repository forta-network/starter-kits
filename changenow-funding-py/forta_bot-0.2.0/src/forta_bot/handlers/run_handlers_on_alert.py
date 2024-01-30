from datetime import datetime
from typing import Callable, Optional
from ..alerts import Alert, CreateAlertEvent, GetAlert
from ..findings import Finding
from ..common import ScanAlertsOptions

RunHandlersOnAlert = Callable[[str | Alert, ScanAlertsOptions, Optional[bool]], list[Finding]]

def provide_run_handlers_on_alert(
    get_alert: GetAlert,
    create_alert_event: CreateAlertEvent,
) -> RunHandlersOnAlert:

  async def run_handlers_on_alert(
      alert_or_hash: str | Alert, 
      options: ScanAlertsOptions, 
      should_stop_on_errors: bool = True) -> list[Finding]:
    handle_alert = options.get('handle_alert')
    if not handle_alert:
      raise Exception("no alert handler provided")
    
    # if passed in a string hash
    if type(alert_or_hash) == str:
      print(f'fetching alert {alert_or_hash}...')
      alert = await get_alert(alert_or_hash)
    else:
      # if passed in an alert
      alert = alert_or_hash
    
    findings = []
    try:
      alert_event = create_alert_event(alert)
      findings = await handle_alert(alert_event)
      # TODO assert_findings(findings)
      print(f'{len(findings)} findings for alert {alert.hash} {findings if len(findings) > 0 else ""}')
    except Exception as e:
      if should_stop_on_errors(): raise e
      print(f'{datetime.now().isoformat()}    handleAlert {alert.hash}')
      print(e)
    
    return findings

  return run_handlers_on_alert