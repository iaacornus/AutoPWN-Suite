from enum import Enum


class ScanMode(Enum):
    NORMAL: int = 0
    NOISE: int = 1
    EVADE: int = 2


class ScanType(Enum):
    PING: int = 0
    ARP: int = 1
