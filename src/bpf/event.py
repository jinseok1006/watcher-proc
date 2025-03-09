import ctypes
from dataclasses import dataclass
from ..config.settings import settings

class ProcessEvent(ctypes.Structure):
    """BPF 이벤트 구조체"""
    _fields_ = [
        ("pid", ctypes.c_uint),                              # 4 bytes
        ("error_flags", ctypes.c_uint),                      # 4 bytes
        ("container_id", ctypes.c_char * settings.CONTAINER_ID_LEN),   # 12 bytes
        ("binary_path", ctypes.c_ubyte * settings.MAX_PATH_LEN),      # 256 bytes
        ("cwd", ctypes.c_ubyte * settings.MAX_PATH_LEN),             # 256 bytes
        ("args", ctypes.c_ubyte * settings.ARGSIZE),                 # 384 bytes
        ("binary_path_offset", ctypes.c_int),                # 4 bytes
        ("cwd_offset", ctypes.c_int),                       # 4 bytes
        ("args_len", ctypes.c_uint32),                      # 4 bytes
        ("exit_code", ctypes.c_int)                         # 4 bytes
    ]                                                       # 총 932 bytes

@dataclass
class ProcessEventData:
    """프로세스 이벤트 데이터"""
    timestamp: str
    pid: int
    process_type: 'ProcessType'  # Forward reference
    binary_path: str
    container_id: str
    cwd: str
    args: str
    error_flags: str
    exit_code: int 