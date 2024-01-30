from enum import IntEnum

class FindingSeverity(IntEnum):
    Unknown = 0
    Info = 1
    Low = 2
    Medium = 3
    High = 4
    Critical = 5