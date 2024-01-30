import asyncio
from datetime import datetime
from aiohttp import web
from typing import Callable, Optional
from ..common import HealthCheck


RunHealthCheck = Callable[[Optional[HealthCheck]], None]

def provide_run_health_check(health_check_port: int):

  async def run_health_check(handler: Optional[HealthCheck] = None):
    # define the HTTP request handler
    async def health_check_handler(request):
      status: int = 200
      errors: list[str] = []
      try:
        if handler:
          response = await handler()
          if response and len(response) > 0:
            errors = response
      except Exception as e:
        print(f'{datetime.now().isoformat()}    handleAlert')
        print(e)
        status = 500
        errors = [str(e)]
      return web.json_response({'errors': errors}, status=status)

    # run the http server
    server = web.Application()
    server.add_routes([web.get('/health', health_check_handler)])
    runner = web.AppRunner(server)
    await runner.setup()
    site = web.TCPSite(runner, port=health_check_port)
    await site.start()

  return run_health_check