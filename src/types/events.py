from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from ..process.types import ProcessType
from ..bpf.event import RawBpfEvent

@dataclass(frozen=True)
class StudentInfo:
    """학생 식별 정보
    
    호스트네임으로부터 파싱된 학생과 과제 관련 정보입니다.
    """
    class_div: str         # 과목-분반 (예: "os-1")
    student_id: str        # 학번 (예: "202012180")
    homework_dir: Optional[str]  # 과제 디렉토리 (예: "hw1")

@dataclass(frozen=True)
class TimestampedEvent:
    """시간 정보와 학생 정보가 추가된 이벤트
    
    RawBpfEvent에 이벤트 발생 시각과 학생 정보가 추가됩니다.
    """
    raw: RawBpfEvent           # 원본 BPF 이벤트
    timestamp: datetime        # 이벤트 발생 시각 (UTC)
    student: StudentInfo       # 학생 식별 정보

    def __getattr__(self, name: str):
        """원본 이벤트의 속성에 접근"""
        if hasattr(self.raw, name):
            return getattr(self.raw, name)
        raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

@dataclass(frozen=True)
class ProcessEvent:
    """프로세스 타입이 결정된 이벤트
    
    TimestampedEvent에 프로세스 타입 정보가 추가됩니다.
    """
    timestamped: TimestampedEvent  # 타임스탬프가 있는 이벤트
    process_type: ProcessType      # 프로세스 타입 (GCC/CLANG/USER_BINARY 등)

    def __getattr__(self, name: str):
        """이전 이벤트의 속성에 접근"""
        if hasattr(self.timestamped, name):
            return getattr(self.timestamped, name)
        raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

@dataclass(frozen=True)
class HomeworkEvent:
    """최종 과제 이벤트
    
    ProcessEvent에 소스 파일 정보가 추가된 최종 이벤트입니다.
    컴파일 이벤트의 경우 소스 파일 정보가 포함됩니다.
    """
    process_event: ProcessEvent
    source_file: Optional[str] = None  # 컴파일 이벤트인 경우의 소스 파일 경로

    def __getattr__(self, name: str):
        """이전 이벤트의 속성에 접근"""
        if hasattr(self.process_event, name):
            return getattr(self.process_event, name)
        raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    @property
    def is_compilation(self) -> bool:
        """컴파일 이벤트 여부"""
        return self.process_type in (ProcessType.GCC, ProcessType.CLANG)

    @property
    def is_execution(self) -> bool:
        """실행 이벤트 여부"""
        return self.process_type == ProcessType.USER_BINARY
