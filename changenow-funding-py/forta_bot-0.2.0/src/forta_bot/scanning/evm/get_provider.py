from typing import Callable
from datetime import datetime
from web3 import AsyncWeb3
from ...utils import FortaConfig
from ...jwt import GetRpcJwt, DecodeJwt
from ...common import ScanEvmOptions
from ..constants import ONE_MIN_IN_SECONDS


GetProvider = Callable[[ScanEvmOptions], AsyncWeb3.AsyncHTTPProvider]

def provide_get_provider(
    get_rpc_jwt: GetRpcJwt,
    decode_jwt: DecodeJwt,
    forta_config: FortaConfig,
    is_prod: bool
) -> GetProvider:

  # maintain a reference to the provider
  provider: AsyncWeb3.AsyncHTTPProvider = None
  # if using rpc_key_id, keep track of when the issued jwt expires so we can refresh
  rpc_jwt_expiration: datetime = None

  async def get_provider(options: ScanEvmOptions) -> AsyncWeb3.AsyncHTTPProvider:
    nonlocal provider
    nonlocal rpc_jwt_expiration
    if provider is not None and not is_jwt_expired(rpc_jwt_expiration):
      return provider

    rpc_url = options.get('rpc_url')
    if rpc_url is None:
      raise Exception("no rpc_url provided")

    rpc_key_id = options.get('rpc_key_id')
    rpc_headers = options.get('rpc_headers')
    rpc_jwt_claims = options.get('rpc_jwt_claims')
    local_rpc_url = options.get('local_rpc_url')
    local_rpc_urls = forta_config.get('localRpcUrls', {})
    headers = {}

    # if there is a locally configured rpc url, use that when not running in production
    if not is_prod and local_rpc_url and local_rpc_url in local_rpc_urls:
      rpc_url = local_rpc_urls[local_rpc_url]
    
    # do jwt token exchange if rpc_key_id provided (only in production)
    if is_prod and rpc_key_id is not None:
      rpc_jwt = await get_rpc_jwt(rpc_url, rpc_key_id, rpc_jwt_claims)
      headers["Authorization"] = f'Bearer {rpc_jwt}'
      rpc_jwt_expiration = datetime.fromtimestamp(decode_jwt(rpc_jwt)['payload']['exp'])

    # set any custom headers
    if rpc_headers is not None:
      headers = {**headers, **rpc_headers}
    
    provider = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc_url, request_kwargs={'headers': headers}))
    return provider
  
  return get_provider


def is_jwt_expired(rpc_jwt_expiration: datetime) -> bool:
  if rpc_jwt_expiration is None: return False

  return rpc_jwt_expiration.timestamp() + ONE_MIN_IN_SECONDS >= datetime.now().timestamp()