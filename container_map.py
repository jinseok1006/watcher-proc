# 외부 주입형 PID-해시 매핑 시스템
class ContainerPIDMap:
    def __init__(self):
        self.data_map = {}  # 외부에서 주입된 PID-해시 저장소
    
    # PID와 해시를 직접 주입 (기존 PID 존재시 덮어쓰기)
    def add(self, pid, container_hash):
        self.data_map[pid] = container_hash
    
    # PID 기반 삭제 (O(1)) - 안전한 삭제로 수정
    def remove(self, pid):
        if pid in self.data_map:  # 존재 여부 확인 추가
            del self.data_map[pid]
    
    # 조회 및 전체 확인 메소드 유지 - pop으로 안전하게 가져오기
    def get(self, pid):
        return self.data_map.pop(pid, None)  # pop with default
    