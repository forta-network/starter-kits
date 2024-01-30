import os
from typing import Callable
from ..utils import assert_exists, FortaConfig


GetTokenExchangeUrl = Callable[[], str]

def provide_get_token_exchange_url(forta_config: FortaConfig):
  assert_exists(forta_config, 'forta_config')

  def get_token_exchange_url() -> str:
    if 'tokenExchangeUrl' in forta_config:
      return forta_config['tokenExchangeUrl']
    
    if 'FORTA_TOKEN_EXCHANGE_URL' in os.environ:
      return os.environ['FORTA_TOKEN_EXCHANGE_URL']
    
    return 'https://alerts.forta.network/exchange-token'

  return get_token_exchange_url