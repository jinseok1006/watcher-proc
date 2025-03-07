from enum import Enum, auto

class ProcessType(Enum):
    """지원하는 프로세스 타입"""
    UNKNOWN = auto()
    GCC = auto()
    CLANG = auto()
    PYTHON = auto()    # 향후 구현
    USER_BINARY = auto() 