from typing import Callable, Optional


GetChainId = Callable[[], Optional[int]]

def provide_get_chain_id(forta_chain_id: Optional[int]):

  def get_chain_id():
    return forta_chain_id
  
  return get_chain_id