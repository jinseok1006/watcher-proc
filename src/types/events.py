from dataclasses import dataclass
from datetime import datetime
from ..process.types import ProcessType
from ..bpf.event import ProcessEventData

@dataclass
class EnrichedProcessEvent:
    """확장된 프로세스 이벤트 데이터"""
    # BPF 이벤트 필드들
    timestamp: str
    pid: int
    process_type: ProcessType
    binary_path: str
    container_id: str
    cwd: str
    args: str
    error_flags: str
    exit_code: int
    
    # 쿠버네티스 관련 확장 필드들
    pod_name: str
    namespace: str
    class_div: str  # e.g. "os-1"
    student_id: str  # e.g. "202012180"
    
    @classmethod
    def from_bpf_event(cls, bpf_event: ProcessEventData, **extra_fields) -> 'EnrichedProcessEvent':
        return cls(
            timestamp=bpf_event.timestamp,
            pid=bpf_event.pid,
            process_type=bpf_event.process_type,
            binary_path=bpf_event.binary_path,
            container_id=bpf_event.container_id,
            cwd=bpf_event.cwd,
            args=bpf_event.args,
            error_flags=bpf_event.error_flags,
            exit_code=bpf_event.exit_code,
            **extra_fields
        ) 