import asyncio
from typing import Callable


Sleep = Callable[[int], None]

def provide_sleep():
  async def sleep(duration_seconds: int):
    await asyncio.sleep(duration_seconds)
  
  return sleep