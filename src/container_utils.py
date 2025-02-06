import os
import re

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
        self.map = {}

    def add(self, pid: int, pod_name: str):
        self.map[pid] = pod_name

    def get(self, pid: int) -> str:
        return self.map.pop(pid) 