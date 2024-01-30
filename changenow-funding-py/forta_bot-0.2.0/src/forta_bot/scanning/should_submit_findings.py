import sys
from datetime import datetime
from typing import Callable
from ..findings import Finding
from .constants import ONE_MIN_IN_SECONDS

ShouldSubmitFindings = Callable[[list[Finding], datetime], bool]

def provide_should_submit_findings(is_prod: bool) -> ShouldSubmitFindings:
  def should_submit_findings(findings: list[Finding], last_submission_timestamp: datetime) -> bool:
    # if running locally, dont submit findings
    if not is_prod: 
      return False

    # if no findings, dont submit
    if len(findings) == 0: 
      return False

    # check if findings byte size is approaching 10MB
    is_byte_size_approaching_10mb = sys.getsizeof(findings) > 9500000
    if is_byte_size_approaching_10mb: 
      return True

    # check if been more than a minute since last submission
    been_more_than_a_minute_since_submission = datetime.now().timestamp() - last_submission_timestamp.timestamp() > ONE_MIN_IN_SECONDS
    return been_more_than_a_minute_since_submission
  
  return should_submit_findings