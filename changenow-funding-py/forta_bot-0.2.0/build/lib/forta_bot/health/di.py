import os
from dependency_injector import containers, providers
from .run_health_check import provide_run_health_check

class HealthContainer(containers.DeclarativeContainer):
  health_check_port = providers.Object(os.environ['FORTA_HEALTH_CHECK_PORT'] if 'FORTA_HEALTH_CHECK_PORT' in os.environ else 3000)
  run_health_check = providers.Callable(provide_run_health_check, 
                                        health_check_port=health_check_port)