import os
from typing import Any, Callable
from .assertions import assert_exists, assert_is_non_empty_string
from .get_forta_config import FortaConfig

GetBotId = Callable[[], str]

def provide_get_bot_id (args: Any, forta_config: FortaConfig) -> GetBotId:
  assert_exists(forta_config, "forta_config")

  def get_bot_id() -> str:
    # if bot id provided by env vars
    if "FORTA_BOT_ID" in os.environ:
      return os.environ["FORTA_BOT_ID"]
    
    # check runtime args for bot id
    if args.get('botId'): return args['botId']
    if args.get('agentId'): return args['agentId']

    # check local config file for bot id (or agent id for backwards compatibility)
    if forta_config.get('agentId'): return forta_config['agentId']
    return assert_is_non_empty_string(forta_config.get('botId'), "botId")
    
  return get_bot_id
