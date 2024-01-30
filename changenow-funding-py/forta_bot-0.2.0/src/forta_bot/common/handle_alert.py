from typing import Callable
from ..alerts import AlertEvent
from ..findings import Finding


HandleAlert = Callable[[AlertEvent], list[Finding]]