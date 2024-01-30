from typing import Callable
import aiohttp

GetAioHttpSession = Callable[[], aiohttp.ClientSession]


AIOHTTP_SESSION = None# maintain a single reference to the session

def provide_get_aiohttp_session():
  
  async def get_aiohttp_session():
      global AIOHTTP_SESSION
      if AIOHTTP_SESSION:
         return AIOHTTP_SESSION

      AIOHTTP_SESSION = aiohttp.ClientSession()
      return AIOHTTP_SESSION
  
  return get_aiohttp_session