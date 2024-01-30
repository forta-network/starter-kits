from typing import Callable, Optional, TypedDict
from datetime import datetime
from .alert import Alert
from ..utils import GetFortaApiUrl, GetFortaApiHeaders, GetAioHttpSession, assert_exists

class GetAlertsCursor:
  def __init__(self, dict):
    self.alert_id: str = dict.get('alertId')
    self.block_number: int = dict.get('blockNumber')

class GetAlertsScanNodeConfirmations(TypedDict):
  gte: int
  lte: int

class GetAlertsBlockDateRange(TypedDict):
  start_date: datetime
  end_date: datetime

class GetAlertsBlockNumberRange(TypedDict):
  start_block_number: int
  end_block_number: int

class GetAlertsInput(TypedDict):
  bot_ids: Optional[list[str]]
  addresses: Optional[list[str]]
  alert_hash: Optional[str]
  alert_id: Optional[str]
  alert_ids: Optional[list[str]]
  chain_id: Optional[int]
  created_since: Optional[int]
  created_before: Optional[int]
  first: Optional[int]
  after: Optional[GetAlertsCursor]
  project_id: Optional[str]
  scan_node_confirmations: Optional[GetAlertsScanNodeConfirmations]
  severities: Optional[list[str]]
  transaction_hash: Optional[str]
  block_sort_direction: Optional[str]
  block_date_range: Optional[GetAlertsBlockDateRange]
  block_number_range: Optional[GetAlertsBlockNumberRange]

class GetAlertsResponsePageInfo:
  def __init__(self, dict):
    self.has_next_page: bool = dict.get('hasNextPage')
    self.end_cursor = GetAlertsCursor(dict.get('endCursor')) if dict.get('endCursor') else None

class GetAlertsResponse:
  def __init__(self, dict):
    self.alerts: list[Alert] = [Alert(a) for a in dict.get('alerts', [])]
    self.page_info = GetAlertsResponsePageInfo(dict.get('pageInfo'))


GetAlerts = Callable[[GetAlertsInput], list[Alert]]

def provide_get_alerts(
    get_aiohttp_session: GetAioHttpSession,
    get_forta_api_url: GetFortaApiUrl,
    get_forta_api_headers: GetFortaApiHeaders
) -> GetAlerts:
  assert_exists(get_aiohttp_session, 'get_aiohttp_session')
  assert_exists(get_forta_api_url, 'get_forta_api_url')
  assert_exists(get_forta_api_headers, 'get_forta_api_headers')

  async def get_alerts(input: GetAlertsInput) -> GetAlertsResponse:
    session = await get_aiohttp_session()
    response = await session.post(
      get_forta_api_url(), 
      json=get_query_from_input(input), 
      headers=get_forta_api_headers())
    
    if response.status == 200:
      return GetAlertsResponse((await response.json()).get('data').get('alerts'))
    else:
      raise Exception(await response.text())

  return get_alerts


def get_query_from_input(input: GetAlertsInput) -> dict:
  vars = {
    'bots': input.get('bot_ids'),
    'addresses': input.get('addresses'),
    'alertHash': input.get('alert_hash'),
    'alertId': input.get('alert_id'),
    'alertIds': input.get('alert_ids'),
    'chainId': input.get('chain_id'),
    'createdSince': input.get('created_since'),
    'createdBefore': input.get('created_before'),
    'first': input.get('first'),
    'after': input.get('after'),
    'projectId': input.get('project_id'),
    'scanNodeConfirmations': input.get('scan_node_confirmations'),
    'severities': input.get('severities'),
    'transactionHash': input.get('transaction_hash'),
    'blockSortDirection': input.get('block_sort_direction')
  }
  if input.get('block_date_range'):
    block_date_range = {}
    if input['block_date_range'].get('start_date'): block_date_range['startDate'] = input['block_date_range']['start_date']
    if input['block_date_range'].get('startDate'): block_date_range['startDate'] = input['block_date_range']['startDate']
    if input['block_date_range'].get('end_date'): block_date_range['endDate'] = input['block_date_range']['end_date']
    if input['block_date_range'].get('endDate'): block_date_range['endDate'] = input['block_date_range']['endDate']
    if block_date_range['startDate']: block_date_range['startDate'] = block_date_range['startDate'].isoformat().split("T")[0]
    if block_date_range['endDate']: block_date_range['endDate'] = block_date_range['endDate'].isoformat().split("T")[0]
    vars['blockDateRange'] = block_date_range
  if input.get('block_number_range'):
    block_number_range = {}
    if input['block_number_rage'].get('start_block_number'): block_number_range['startBlockNumber'] = input['block_number_rage']['start_block_number']
    if input['block_number_rage'].get('startBlockNumber'): block_number_range['startBlockNumber'] = input['block_number_rage']['startBlockNumber']
    if input['block_number_rage'].get('end_block_number'): block_number_range['endBlockNumber'] = input['block_number_rage']['end_block_number']
    if input['block_number_rage'].get('endBlockNumber'): block_number_range['endBlockNumber'] = input['block_number_rage']['endBlockNumber']
    vars['blockNumberRange'] = block_number_range

  query = """
    query($input: AlertsInput) {
      alerts(input: $input) {
          alerts {
              alertId
              addresses
              contracts {
                  address
                  name
                  projectId
              }
              createdAt
              description
              hash
              metadata
              name
              projects {
                  id
              }
              protocol
              scanNodeCount
              severity
              source {
                  transactionHash
                  bot {
                      chainIds
                      createdAt
                      description
                      developer
                      docReference
                      enabled
                      id
                      image
                      name
                      reference
                      repository
                      projects
                      scanNodes
                      version
                  }
                  block {
                      number
                      hash
                      timestamp
                      chainId
                  }
                  sourceAlert {
                      hash
                      botId
                      timestamp
                      chainId
                  }
              }
              alertDocumentType
              findingType
              relatedAlerts
              chainId
              labels {
                  label
                  confidence
                  entity
                  entityType
                  remove
                  metadata
                  uniqueKey
              }
              addressBloomFilter {
                  bitset
                  k
                  m
              }
          }
          pageInfo {
              hasNextPage
              endCursor {
                  blockNumber
                  alertId
              }
          }
      }
    }
    """
  return dict(query=query, variables={'input': {k: v for k,v in vars.items() if v}})
  