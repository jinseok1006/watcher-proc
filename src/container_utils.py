import os
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class ProcessInfo:
    """프로세스 정보를 저장하는 데이터 클래스"""
    container_hash: str
    exe_path: str      # 실행 파일 전체 경로
    cmdline: str       # 실행 명령어 전체

def get_process_path(pid: int) -> str:
    """프로세스의 실행 파일 경로 반환"""
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
        return exe_path
    except:
        return "unknown"

def get_process_cmdline(pid: int) -> str:
    """프로세스의 전체 명령어 반환"""
    try:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            return f.read().replace('\x00', ' ').strip()
    except:
        return "unknown"

def get_container_id(pid: int) -> str:
    """
    PID를 이용해 컨테이너 ID 추출
    - /proc/<pid>/cgroup 파일에서 Docker 컨테이너 해시 검색
    - 컨테이너가 아닌 경우 빈 문자열 반환
    """
    cgroup_file = f"/proc/{pid}/cgroup"
    if not os.path.exists(cgroup_file):
        return "unknown"
    try:
        with open(cgroup_file, "r") as f:
            for line in f:
                parts = line.strip().split(":", 2)
                if len(parts) < 3:
                    continue
                cgroup_path = parts[2]
                # Docker 컨테이너 ID 패턴 검색
                m = re.search(r"/docker/([0-9a-f]{12,64})", cgroup_path)
                if m:
                    return m.group(1)
                m = re.search(r"docker-([0-9a-f]{12,64})\.scope", cgroup_path)
                if m:
                    return m.group(1)
    except Exception:
        return "unknown"


class HashPIDMap:
    def __init__(self):
        # PID를 키로 하고 ProcessInfo를 값으로 저장
        self.map: dict[int, ProcessInfo] = {}

    def add(self, pid: int, container_hash: str):
        # 프로세스 정보 수집
        exe_path = get_process_path(pid)
        cmdline = get_process_cmdline(pid)
        
        # ProcessInfo 객체 생성 및 저장
        self.map[pid] = ProcessInfo(
            container_hash=container_hash,
            exe_path=exe_path,
            cmdline=cmdline
        )

    def get(self, pid: int) -> ProcessInfo:
        # PID에 해당하는 ProcessInfo 반환 및 맵에서 제거
        return self.map.pop(pid) 