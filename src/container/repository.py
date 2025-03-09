from typing import Dict, Optional, Set, Tuple
import logging

class ContainerHashRepository:
    """컨테이너 해시와 파드 정보를 저장하는 저장소"""
    def __init__(self):
        # 파드 정보 저장소: (namespace, pod_name) -> {container_hashes: set(), pod_info: dict}
        self.pods: Dict[Tuple[str, str], dict] = {}
        # 컨테이너 해시 -> (namespace, pod_name) 매핑
        self.container_to_pod: Dict[str, Tuple[str, str]] = {}
        self.logger = logging.getLogger(__name__)

    def save_pod_containers(self, namespace: str, pod_name: str, container_hashes: Set[str], pod_info: dict) -> None:
        """파드와 그 컨테이너 정보 저장/업데이트
        
        Args:
            namespace: 파드의 네임스페이스
            pod_name: 파드 이름
            container_hashes: 정확히 12자리의 컨테이너 해시 집합
            pod_info: 파드 정보 (반드시 'pod_name'과 'namespace' 키를 포함해야 함)
            
        Raises:
            ValueError: pod_info에 필수 키가 없거나, 해시가 12자리가 아닌 경우
        """
        if not all(key in pod_info for key in ['pod_name', 'namespace']):
            raise ValueError("pod_info must contain 'pod_name' and 'namespace'")
            
        # 모든 해시가 정확히 12자리인지 검증
        if not all(len(h) == 12 for h in container_hashes):
            raise ValueError("All container hashes must be exactly 12 characters long")
            
        pod_key = (namespace, pod_name)
        
        # 이전 컨테이너 해시 정보 가져오기
        old_container_hashes = set()
        if pod_key in self.pods:
            old_container_hashes = self.pods[pod_key]['container_hashes']
        
        # 새로운 정보 저장
        self.pods[pod_key] = {
            'container_hashes': container_hashes,
            'pod_info': pod_info
        }
        
        # 컨테이너 해시 -> 파드 매핑 업데이트
        # 1. 삭제된 컨테이너 매핑 제거
        removed_hashes = old_container_hashes - container_hashes
        for removed_hash in removed_hashes:
            self.container_to_pod.pop(removed_hash, None)
        
        # 2. 새로운/유지되는 컨테이너 매핑
        for container_hash in container_hashes:
            self.container_to_pod[container_hash] = pod_key

    def find_by_hash(self, container_hash: str) -> Optional[dict]:
        """컨테이너 해시로 파드 정보 조회
        
        Args:
            container_hash: 정확히 12자리의 컨테이너 해시
            
        Returns:
            파드 정보 또는 None (해시가 존재하지 않는 경우)
            
        Raises:
            ValueError: 해시가 12자리가 아닌 경우
        """
        if not container_hash or len(container_hash) != 12:
            raise ValueError("Container hash must be exactly 12 characters long")
            
        pod_key = self.container_to_pod.get(container_hash)
        if pod_key and pod_key in self.pods:
            return self.pods[pod_key]['pod_info']
        return None

    def remove_pod_containers(self, pod_name: str, namespace: str) -> None:
        """파드 및 관련 컨테이너 정보 삭제"""
        pod_key = (namespace, pod_name)
        if pod_key in self.pods:
            # 컨테이너 해시 매핑 제거
            for container_hash in self.pods[pod_key]['container_hashes']:
                self.container_to_pod.pop(container_hash, None)
            # 파드 정보 제거
            self.pods.pop(pod_key)

    def print_current_state(self) -> None:
        """현재 저장소 상태 출력"""
        self.logger.info("[상태] 현재 컨테이너 매핑 상태")
        if not self.pods:
            self.logger.info("(비어있음)")
            return
            
        # 네임스페이스별로 그룹화하여 출력
        by_namespace = {}
        for (ns, pod_name), pod_data in self.pods.items():
            if ns not in by_namespace:
                by_namespace[ns] = []
            by_namespace[ns].append((pod_name, pod_data['container_hashes']))
        
        # 정렬된 출력
        for ns in sorted(by_namespace.keys()):
            self.logger.info(f"[상태] 네임스페이스: {ns}")
            for pod_name, container_hashes in sorted(by_namespace[ns]):
                self.logger.info(f"[상태]   파드: {pod_name}")
                for hash_val in sorted(container_hashes):
                    self.logger.info(f"[상태]     - 컨테이너: {hash_val}")

