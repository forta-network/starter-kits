from typing import Callable, TypedDict
import json
from ..utils import assert_exists, snake_to_camel_case, GetFortaApiUrl, GetFortaApiHeaders, GetAioHttpSession
from ..findings import Finding, FindingType, FindingSeverity
from ..labels import EntityType


class SendAlertsInput(TypedDict):
  bot_id: str
  finding: Finding

class SendAlertError(TypedDict):
  code: str
  message: str

class SendAlertsResponse(TypedDict):
  alert_hash: str
  error: SendAlertError


SendAlerts = Callable[[list[SendAlertsInput] | SendAlertsInput], SendAlertsResponse]

def provide_send_alerts(
    get_aiohttp_session: GetAioHttpSession,
    get_forta_api_url: GetFortaApiUrl,
    get_forta_api_headers: GetFortaApiHeaders) -> SendAlerts:
  assert_exists(get_aiohttp_session, 'get_aiohttp_session')
  assert_exists(get_forta_api_url, 'get_forta_api_url')
  assert_exists(get_forta_api_headers, 'get_forta_api_headers')

  async def send_alerts(input: list[SendAlertsInput] | SendAlertsInput) -> list[SendAlertsResponse]:
    if not type(input) == list:
      input = [input]
    
    session = await get_aiohttp_session()
    response = await session.post(
       get_forta_api_url(), 
       json=get_mutation_from_input(input), 
       headers=get_forta_api_headers())

    if response.status == 200:
       send_alerts_response = (await response.json()).get('data').get('sendAlerts').get('alerts')
       print('send_alerts_response', send_alerts_response)
       # TODO check for any errors, surface them and mark the finding for retry
       return [{**item, 'alert_hash': item['alertHash']} for item in send_alerts_response]
    else:
       raise Exception(await response.text())

  return send_alerts


def get_mutation_from_input(inputs: list[SendAlertsInput]) -> dict:
  mutation = """
  mutation SendAlerts($alerts: [AlertRequestInput!]!) {
      sendAlerts(alerts: $alerts) {
          alerts {
              alertHash
              error {
                  code
                  message
              }
          }
      }
  }
  """
  alerts = []
  # serialize the inputs list
  for input in inputs:
      # convert finding timestamp to RFC3339 format
      input["finding"].timestamp = input["finding"].timestamp.astimezone().isoformat()
      # serialize finding
      finding = json.loads(repr(input["finding"]))
      # convert enums to all caps to match graphql enums
      finding["type"] = FindingType(finding["type"]).name.upper()
      finding["severity"] = FindingSeverity(
          finding["severity"]).name.upper()
      for label in finding.get("labels", []):
          label["entityType"] = EntityType(
              label["entityType"]).name.upper()
      # remove protocol field (not part of graphql schema)
      if 'protocol' in finding:
        del finding["protocol"] 
      # remove any empty-value fields and convert snake-case keys to camel-case
      finding = {snake_to_camel_case(k): v for k, v in finding.items() if v is not None}
      for index, label in enumerate(finding.get("labels", [])):
          finding["labels"][index] = {k: v for k, v in label.items()
                                      if v is not None and "_" not in k}
      alerts.append({
          "botId": input["bot_id"],
          "finding": finding
      })

  return {
    'query': mutation,
    'variables': {
      'alerts': alerts
      }
  }