import asyncio
from typing import Callable, Optional
from ...alerts import Alert, AlertSubscription, GetAlerts, GetAlertsResponse
from ...utils import assert_exists

GetAlertsForSubscriptions = Callable[[list[AlertSubscription]], list[Alert]]

TEN_MINUTES_IN_MS = 600000

def provide_get_alerts_for_subscriptions(get_alerts: GetAlerts):
  assert_exists(get_alerts, 'get_alerts')

  # maintain an in-memory map to keep track of alerts that have been seen (used for de-duping)
  seen_alerts: {str: bool} = {}# TODO use LRU cache instead of map

  async def get_alerts_for_subscriptions(subscriptions: list[AlertSubscription]) -> list[Alert]:
    nonlocal seen_alerts

    # run a query for each subscription (this keeps response payloads small to avoid API Gateway 10MB limit)
    queries = []
    for subscription in subscriptions:
      queries.append(run_query(subscription, get_alerts))
    alert_arrays = await asyncio.gather(*queries)

    # flatten and de-dupe the responses
    alerts: list[Alert] = []
    for alert_array in alert_arrays:
      for alert in alert_array:
        if alert.hash in seen_alerts: continue # skip alerts we have already processed
        alerts.append(alert)
        seen_alerts[alert.hash] = True
    
    return alerts

  return get_alerts_for_subscriptions


async def run_query(subscription: AlertSubscription, get_alerts: GetAlerts) -> list[Alert]:
  alerts: list[Alert] = []
  page_size = 1000
  should_retry_from_error = False
  response: Optional[GetAlertsResponse] = None

  while True:
    try:
      query = {
        'bot_ids': [subscription.get('bot_id')],
        'created_since': TEN_MINUTES_IN_MS,
        'first': page_size,
      }
      if response and response.page_info.end_cursor:
        query['starting_cursor'] = response.page_info.end_cursor
      if subscription.get('chain_id'):
        query['chain_id'] = subscription['chain_id']
      if subscription.get('alert_id'):
        query['alert_ids'] = [subscription['alert_id']]
      if subscription.get('alert_ids'):
        if not 'alert_ids' in query: query['alert_ids'] = []
        query['alert_ids'] = query['alert_ids'] + subscription['alert_ids']

      response = await get_alerts(query)
      should_retry_from_error = False
      alerts = alerts + response.alerts
    except Exception as e:
      # if alerts API returned error, its likely due to response size being over 10MB AWS gateway limit
      page_size = int(page_size/2) # reduce the page size in order to reduce response size and try again
      should_retry_from_error = page_size > 1
      if not should_retry_from_error: raise e

    if not should_retry_from_error and not(response and response.page_info.has_next_page):
      break
  
  return alerts