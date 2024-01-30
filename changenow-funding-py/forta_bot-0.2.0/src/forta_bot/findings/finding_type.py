from enum import IntEnum

class FindingType(IntEnum):
    Unknown = 0
    Exploit = 1
    Suspicious = 2
    Degraded = 3
    Info = 4
    Scam = 5