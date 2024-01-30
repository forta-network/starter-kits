from dependency_injector import containers, providers
from .get_trace_data import provide_get_trace_data


class TracesContainer(containers.DeclarativeContainer):
  get_trace_data = providers.Callable(provide_get_trace_data)