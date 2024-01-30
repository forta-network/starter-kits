from typing import Callable, Optional
from datetime import datetime
from ...utils import Sleep, GetBotId
from ...cli import RunCliCommand
from ...alerts import SendAlerts
from ...handlers import RunHandlersOnAlert
from ...common import ScanAlertsOptions
from ..should_submit_findings import ShouldSubmitFindings
from ..should_stop_on_errors import ShouldStopOnErrors
from ..constants import ONE_MIN_IN_SECONDS
from .get_alerts_for_subscriptions import GetAlertsForSubscriptions

ScanAlerts = Callable[[ScanAlertsOptions], None]

def provide_scan_alerts(
    is_running_cli_command: bool,
    run_cli_command: RunCliCommand,
    get_bot_id: GetBotId,
    get_alerts_for_subscriptions: GetAlertsForSubscriptions,
    run_handlers_on_alert: RunHandlersOnAlert,
    send_alerts: SendAlerts,
    should_submit_findings: ShouldSubmitFindings,
    should_stop_on_errors: ShouldStopOnErrors,
    sleep: Sleep,
    forta_shard_id: Optional[int],
    forta_shard_count: Optional[int],
    should_continue_polling: Callable = lambda: True
) -> ScanAlerts:

  async def scan_alerts(options: ScanAlertsOptions):
    handle_alert = options.get('handle_alert')
    subscriptions = options.get('subscriptions')
    if not handle_alert:
      raise Exception("no alert handler provided")
    if not subscriptions or len(subscriptions) == 0:
      raise Exception("no alert subscriptions provided")
    
    if is_running_cli_command:
      await run_cli_command({'scan_alerts_options': options})
      return
    
    bot_id = get_bot_id()
    last_submission_timestamp = datetime.now() # initialize to now
    findings = []

    while(should_continue_polling()):
      print('querying alerts...')
      alerts = await get_alerts_for_subscriptions(subscriptions)
      print(f'found {len(alerts)} alerts')
      for alert in alerts:
        # check if this alert should be processed
        if is_alert_on_this_shard(alert.created_at, forta_shard_id, forta_shard_count):
          findings.extend(await run_handlers_on_alert(alert, options, should_stop_on_errors()))
      
      # check if should submit any findings
      if should_submit_findings(findings, last_submission_timestamp):
        await send_alerts([{'bot_id': bot_id, 'finding': f} for f in findings])
        findings = [] # clear array
        last_submission_timestamp = datetime.now() # remember timestamp

      # wait a minute before querying again
      await sleep(ONE_MIN_IN_SECONDS)

  return scan_alerts


def is_alert_on_this_shard(alert_timestamp: str, shard_id: Optional[int], shard_count: Optional[int]):
  # if bot is not sharded
  if not shard_id or not shard_count:
    return True # process everything
  
  # process alert if timestamp modulo shard_count equals shard_id
  timestamp = int(datetime.fromisoformat(alert_timestamp.replace("T", " ").replace("Z","")[:alert_timestamp.index(".")]).timestamp())
  return timestamp % shard_count == shard_id

  