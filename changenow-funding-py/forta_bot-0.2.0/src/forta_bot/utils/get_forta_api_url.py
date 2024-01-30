import os
from typing import Callable
from .assertions import assert_exists
from .get_forta_config import FortaConfig

GetFortaApiUrl = Callable[[], str]

def provide_get_forta_api_url(forta_config: FortaConfig) -> GetFortaApiUrl:
  assert_exists(forta_config, 'forta_config')

  def get_forta_api_url() -> str:
    # if provided by scanner i.e. in production
    if 'FORTA_PUBLIC_API_PROXY_HOST' in os.environ:
      port = f':{os.environ["FORTA_PUBLIC_API_PROXY_PORT"]}' if "FORTA_PUBLIC_API_PROXY_PORT" in os.environ else ""
      return f'http://{os.environ["FORTA_PUBLIC_API_PROXY_HOST"]}{port}/graphql'
    
    # if provided via env var
    if "FORTA_API_URL" in os.environ:
      return os.environ["FORTA_API_URL"]
    
    if forta_config.get('fortaApiUrl'):
      return forta_config['fortaApiUrl']
    
    return "https://api.forta.network/graphql"

  return get_forta_api_url