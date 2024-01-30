from dependency_injector import containers, providers
from .run_transaction import provide_run_transaction
from .run_block import provide_run_block
from .run_alert import provide_run_alert
from .run_block_range import provide_run_block_range
from .run_cli_command import provide_run_cli_command

class CliContainer(containers.DeclarativeContainer):
  common = providers.DependenciesContainer()
  transactions = providers.DependenciesContainer()
  handlers = providers.DependenciesContainer()

  run_transaction = providers.Callable(provide_run_transaction,
                                       run_handlers_on_transaction=handlers.run_handlers_on_transaction)
  run_block = providers.Callable(provide_run_block,
                                 run_handlers_on_block=handlers.run_handlers_on_block)
  run_alert = providers.Callable(provide_run_alert,
                                 run_handlers_on_alert=handlers.run_handlers_on_alert)
  run_block_range = providers.Callable(provide_run_block_range,
                                       run_handlers_on_block=handlers.run_handlers_on_block)
  run_cli_command = providers.Callable(provide_run_cli_command,
                                       get_aiohttp_session=common.get_aiohttp_session,
                                       run_transaction=run_transaction,
                                       run_block=run_block,
                                       run_alert=run_alert,
                                       run_block_range=run_block_range)