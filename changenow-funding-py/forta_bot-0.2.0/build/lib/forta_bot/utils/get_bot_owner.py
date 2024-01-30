

from typing import Callable


GetBotOwner = Callable[[], str]


def provide_get_bot_owner(forta_bot_owner: str):

  def get_bot_owner() -> str:
    return forta_bot_owner
  
  return get_bot_owner