from typing import Dict, Any, List, Set
import os
import logging

class Settings:
    """애플리케이션 설정
    
    모든 환경 변수 기반 설정을 중앙 집중적으로 관리합니다.
    """
    
    # 프로세스 패턴 (상수)
    PROCESS_PATTERNS: Dict[str, List[str]] = {
        'GCC': ['/usr/bin/x86_64-linux-gnu-gcc-13', '/usr/bin/x86_64-linux-gnu-gcc-12'],
        'CLANG': ['/usr/lib/llvm-18/bin/clang', '/usr/lib/llvm-17/bin/clang', '/usr/lib/llvm-16/bin/clang'],
        'PYTHON': ['/usr/bin/python3.12', '/usr/bin/python3.11', '/usr/bin/python3.10', '/usr/bin/python3.9']
    }
    
    # BPF 관련 상수
    CONTAINER_ID_LEN: int = 12
    MAX_PATH_LEN: int = 256
    ARGSIZE: int = 384
    
    # 컴파일러 설정
    COMPILER_SKIP_OPTIONS: Set[str] = {'-o', '-I', '-include', '-D', '-U', '-MF'}
    
    def __init__(self):
        # 로깅 설정
        self.log_level: str = os.getenv('LOG_LEVEL', 'INFO').upper()
        self.log_format: str = os.getenv(
            'LOG_FORMAT',
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # 쿠버네티스 설정
        self.watch_namespaces: list = os.getenv(
            'WATCH_NAMESPACES',
            'jcode-os-1,watcher'
        ).split(',')
        
        # 프로젝트 설정
        self.project_root: str = os.getenv('PROJECT_ROOT', '/home/coder/project')
    
    @property
    def log_level_enum(self) -> int:
        """로깅 레벨을 logging 모듈의 상수값으로 변환"""
        log_level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return log_level_map.get(self.log_level, logging.INFO)
    
    def as_dict(self) -> Dict[str, Any]:
        """설정값들을 딕셔너리로 반환"""
        return {
            'log_level': self.log_level,
            'log_format': self.log_format,
            'watch_namespaces': self.watch_namespaces,
            'project_root': self.project_root
        }
    
    def __str__(self) -> str:
        """설정값들을 문자열로 반환"""
        return f"Settings({', '.join(f'{k}={v}' for k, v in self.as_dict().items())})"

# 싱글톤 인스턴스 생성
settings = Settings() 