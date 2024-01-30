from typing import Callable
from .block_event import BlockEvent

CreateBlockEvent = Callable[[dict, int], BlockEvent]

def provide_create_block_event() -> CreateBlockEvent:

  def create_block_event(block: dict, network_id: int):
    return BlockEvent({'network': network_id, 'block': block})

  return create_block_event