import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

from src.handlers.chain import build_handler_chain
from src.events.models import EventBuilder, ProcessTypeInfo, HomeworkInfo
from src.bpf.event import RawBpfEvent
from src.process.types import ProcessType
from src.process.filter import ProcessFilter
from src.homework.base import HomeworkChecker

class MockHomeworkChecker(HomeworkChecker):
    """테스트용 과제 체커"""
    def __init__(self, homework_dirs: list[str]):
        self.homework_dirs = homework_dirs
        
    def get_homework_info(self, binary_path: str) -> str | None:
        """과제 디렉토리 확인"""
        for hw_dir in self.homework_dirs:
            if hw_dir in binary_path:
                return hw_dir
        return None

class MockProcessFilter(ProcessFilter):
    """테스트용 프로세스 필터"""
    def __init__(self):
        # settings와 homework_checker 모킹
        with patch('src.process.filter.settings') as mock_settings:
            mock_settings.PROCESS_PATTERNS = {
                'GCC': ['/usr/bin/gcc'],
                'CLANG': ['/usr/bin/clang'],
                'PYTHON': ['/usr/bin/python3']
            }
            super().__init__(MockHomeworkChecker(["/home/student/hw1", "/home/student/hw2"]))

@pytest.fixture
def homework_checker():
    """테스트용 과제 체커"""
    return MockHomeworkChecker(["/home/student/hw1", "/home/student/hw2"])

@pytest.fixture
def process_filter():
    """테스트용 프로세스 필터"""
    return MockProcessFilter()

@pytest.fixture
def handler_chain(process_filter):
    """테스트용 핸들러 체인"""
    return build_handler_chain(
        process_filter=process_filter,
        homework_checker=process_filter.hw_checker,
        use_api=False  # API 핸들러는 제외
    )

@pytest.fixture
def gcc_event():
    """GCC 컴파일러 실행 이벤트"""
    return RawBpfEvent(
        hostname="jcode-os-1-202012180-hash",
        pid=1234,
        binary_path="/usr/bin/gcc",
        cwd="/home/student/hw1",
        args="gcc -o main main.c",
        error_flags="0",
        exit_code=0
    )

@pytest.fixture
def binary_event():
    """과제 실행 파일 실행 이벤트"""
    return RawBpfEvent(
        hostname="jcode-os-1-202012180-hash",
        pid=1235,
        binary_path="/home/student/hw1/main",
        cwd="/home/student/hw1",
        args="./main arg1 arg2",
        error_flags="0",
        exit_code=0
    )

@pytest.mark.asyncio
async def test_handle_gcc_compilation(handler_chain, gcc_event):
    """GCC 컴파일 이벤트 처리 테스트"""
    # Given
    builder = EventBuilder(gcc_event)
    
    # When
    result = await handler_chain.handle(builder)
    
    # Then
    assert result is not None
    assert result.process.type == ProcessType.GCC
    assert result.metadata.class_div == "os-1"
    assert result.metadata.student_id == "202012180"
    assert isinstance(result.homework, HomeworkInfo)
    assert result.homework.homework_dir == "/home/student/hw1"
    assert result.homework.source_file == "main.c"

@pytest.mark.asyncio
async def test_handle_binary_execution(handler_chain, binary_event):
    """과제 실행 파일 실행 이벤트 처리 테스트"""
    # Given
    builder = EventBuilder(binary_event)
    
    # When
    result = await handler_chain.handle(builder)
    
    # Then
    assert result is not None
    assert result.process.type == ProcessType.USER_BINARY
    assert result.metadata.class_div == "os-1"
    assert result.metadata.student_id == "202012180"
    assert isinstance(result.homework, HomeworkInfo)
    assert result.homework.homework_dir == "/home/student/hw1"
    assert result.homework.source_file is None

@pytest.mark.asyncio
async def test_handle_unknown_process(handler_chain):
    """알 수 없는 프로세스 이벤트 처리 테스트"""
    # Given
    event = RawBpfEvent(
        hostname="jcode-os-1-202012180-hash",
        pid=1236,
        binary_path="/usr/bin/ls",
        cwd="/home/student",
        args="ls -l",
        error_flags="0",
        exit_code=0
    )
    builder = EventBuilder(event)
    
    # When
    result = await handler_chain.handle(builder)
    
    # Then
    assert result is None  # ProcessTypeHandler에서 UNKNOWN 타입은 None 반환

@pytest.mark.asyncio
async def test_handle_non_homework_compilation(handler_chain):
    """과제 디렉토리 외부에서의 컴파일 이벤트 처리 테스트"""
    # Given
    event = RawBpfEvent(
        hostname="jcode-os-1-202012180-hash",
        pid=1237,
        binary_path="/usr/bin/gcc",
        cwd="/home/student/other",
        args="gcc -o test test.c",
        error_flags="0",
        exit_code=0
    )
    builder = EventBuilder(event)
    
    # When
    result = await handler_chain.handle(builder)
    
    # Then
    assert result is not None
    assert result.process.type == ProcessType.GCC
    assert result.metadata.class_div == "os-1"
    assert result.metadata.student_id == "202012180"
    assert result.homework is None

@pytest.mark.asyncio
async def test_handle_gcc_compilation_with_logging(handler_chain, gcc_event, caplog):
    """GCC 컴파일 이벤트 처리 및 로깅 테스트"""
    # Given
    builder = EventBuilder(gcc_event)
    
    # When
    result = await handler_chain.handle(builder)
    
    # Then
    assert result is not None
    assert "=== 이벤트 파싱 완료 ===" in caplog.text
    assert "프로세스: GCC" in caplog.text
    assert "실행 파일: /usr/bin/gcc" in caplog.text
    assert "=== 메타데이터 ===" in caplog.text
    assert "분반: os-1" in caplog.text
    assert "학번: 202012180" in caplog.text
    assert "=== 과제 정보 ===" in caplog.text
    assert "과제 디렉토리: /home/student/hw1" in caplog.text
    assert "소스 파일: main.c" in caplog.text