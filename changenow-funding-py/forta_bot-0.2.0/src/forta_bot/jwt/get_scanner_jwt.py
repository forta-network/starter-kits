from datetime import datetime
from typing import Callable, Optional
from ..utils import assert_exists, GetAioHttpSession
from .constants import MOCK_SCANNER_JWT

GetScannerJwt = Callable[[object, Optional[datetime]], str]

def provide_get_scanner_jwt(
    get_aiohttp_session: GetAioHttpSession,
    is_prod: bool,
    forta_jwt_provider_host: str,
    forta_jwt_provider_port: int
    ) -> GetScannerJwt:
  assert_exists(get_aiohttp_session, 'get_aiohttp_session')

  async def get_scanner_jwt(claims: object = {}, expires_at: Optional[datetime] = None) -> str:
    if not is_prod: return MOCK_SCANNER_JWT 
  
    if expires_at is not None:
      claims = {'exp': expires_at.timestamp(), **claims}

    session = await get_aiohttp_session()
    response = await session.post(
      f'http://{forta_jwt_provider_host}:{forta_jwt_provider_port}/create', 
      json={'claims': claims})
    
    if response.status == 200:
      return (await response.json(content_type=None))['token']
    else:
      raise Exception(await response.text())

  return get_scanner_jwt
