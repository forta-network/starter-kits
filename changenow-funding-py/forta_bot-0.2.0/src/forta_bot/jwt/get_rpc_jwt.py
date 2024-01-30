from typing import Callable, Optional
from ..utils import assert_exists, GetAioHttpSession
from .get_scanner_jwt import GetScannerJwt
from .get_token_exchange_url import GetTokenExchangeUrl

GetRpcJwt = Callable[[str, str, Optional[dict]], str]

def provide_get_rpc_jwt(
    get_aiohttp_session: GetAioHttpSession,
    get_scanner_jwt: GetScannerJwt, 
    get_token_exchange_url: GetTokenExchangeUrl, 
    ) -> GetRpcJwt:
  assert_exists(get_aiohttp_session, 'get_aiohttp_session')
  assert_exists(get_scanner_jwt, "get_scanner_jwt")
  assert_exists(get_token_exchange_url, "get_token_exchange_url")

  async def get_rpc_jwt(rpc_url: str, rpc_key_id: str, rpc_jwt_claims: dict = {}) -> str:
    if not rpc_jwt_claims:
      rpc_jwt_claims = {}
      
    jwt_data = {
      'kid': rpc_key_id,
      'claims': {
        'access': 'token_exchange',
        **rpc_jwt_claims
      }
    }

    # infura expects an extra aud claim (which should be set to "infura.io")
    if "infura" in rpc_url:
      jwt_data['claims']['aud'] = 'infura.io'

    # fetch the scanner JWT
    scanner_jwt = await get_scanner_jwt(jwt_data['claims'])

    # exchange scanner JWT for RPC JWT using token exchange server
    session = await get_aiohttp_session()
    response = await session.post(
      get_token_exchange_url(), 
      json=jwt_data, 
      headers={'Authorization': f'Bearer {scanner_jwt}'})

    if response.status == 200:
      return (await response.json(content_type=None))['token']
    else:
      raise Exception(await response.text())

  return get_rpc_jwt