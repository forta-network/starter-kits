from typing import Callable, Optional


HealthCheck = Callable[[], Optional[list[str]]]