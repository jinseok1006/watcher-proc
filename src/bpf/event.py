import ctypes
from dataclasses import dataclass
from ..config.settings import settings

class ProcessEvent(ctypes.Structure):
    """BPF 이벤트 구조체"""
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("ppid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("container_id", ctypes.c_char * settings.CONTAINER_ID_LEN),
        ("binary_path", ctypes.c_ubyte * settings.MAX_PATH_LEN),
        ("cwd", ctypes.c_ubyte * settings.MAX_PATH_LEN),
        ("args", ctypes.c_ubyte * settings.ARGSIZE),
        ("error_code", ctypes.c_uint),
        ("binary_path_offset", ctypes.c_int),
        ("cwd_offset", ctypes.c_int),
        ("args_len", ctypes.c_uint32),
        ("exit_code", ctypes.c_int)
    ]

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