from dependency_injector import containers, providers
from .get_logs_for_block import provide_get_logs_for_block


class LogsContainer(containers.DeclarativeContainer):
  get_logs_for_block = providers.Callable(provide_get_logs_for_block)