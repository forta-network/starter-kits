from typing import Callable
from ..utils import FortaConfig

ShouldStopOnErrors = Callable[[], bool]

def provide_should_stop_on_errors(forta_config: FortaConfig, is_prod: bool):

  def should_stop_on_errors():
    if forta_config.get('shouldStopOnErrors') is not None:
      return forta_config.get('shouldStopOnErrors')
    
    # stop execution on errors by default in dev
    return not is_prod 

  return should_stop_on_errors