import os
import re

def get_container_id(pid: int) -> str:
    """
    PID를 이용해 파드 이름 추출
    - /proc/<pid>/cgroup 파일에서 쿠버네티스 파드 이름 검색
    """
    cgroup_file = f"/proc/{pid}/cgroup"
    if not os.path.exists(cgroup_file):
        return ""
    try:
        with open(cgroup_file, "r") as f:
            for line in f:
                parts = line.strip().split(":", 2)
                if len(parts) < 3:
                    continue
                cgroup_path = parts[2]
                
                # 쿠버네티스 파드 이름 패턴 (기본 형식)
                m = re.search(r"/kubepods[^/]*/pod([a-f0-9-]+)/([0-9a-f]{64})", cgroup_path)
                if not m:
                    # 대체 형식 (containerd 기준)
                    m = re.search(r"cri-containerd-([0-9a-f]{64})\.scope", cgroup_path)
                
                if m:
                    # 컨테이너 런타임에서 파드 이름 조회
                    container_id = m.group(2) if m.group(0).startswith('/kubepods') else m.group(1)
                    return get_pod_name_from_runtime(container_id)
                    
    except Exception:
        return ""
    return ""

# 파드 이름 조회를 위한 도우미 함수 추가
def get_pod_name_from_runtime(container_id: str) -> str:
    """컨테이너 런타임에서 파드 이름 조회"""
    try:
        # crictl을 사용해 컨테이너 정보 조회
        cmd = f"crictl inspect {container_id} | jq -r '.status.labels[\"io.kubernetes.pod.name\"]'"
        pod_name = os.popen(cmd).read().strip()
        return pod_name if pod_name else "unknown"
    except Exception:
        return "unknown"
