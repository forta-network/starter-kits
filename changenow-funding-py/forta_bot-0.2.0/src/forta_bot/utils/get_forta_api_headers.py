import os
from typing import Callable
from .assertions import assert_exists
from .get_forta_config import FortaConfig

GetFortaApiHeaders = Callable[[], dict]

def provide_get_forta_api_headers(forta_config: FortaConfig):
  assert_exists(forta_config, 'forta_config')

  def get_forta_api_headers():
    headers = { 'Content-Type': 'application/json'}

    # try the api key specified in env vars first
    if "FORTA_API_KEY" in os.environ:
      headers['Authorization'] = f'Bearer {os.environ["FORTA_API_KEY"]}'
    elif 'fortaApiKey' in forta_config:
      # use the api key from forta config (only for local development)
      headers['Authorization'] = f'Bearer {forta_config["fortaApiKey"]}'
    
    return headers
  
  return get_forta_api_headers