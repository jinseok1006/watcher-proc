from kubernetes import client
import logging
from datetime import datetime
from typing import Dict, List
from .config.settings import Settings

class ContainerToPodMapper:
    def __init__(self):
        self.hash_to_pod: Dict[str, dict] = {}
        self.target_namespaces = Settings.get_target_namespaces()

    def update_index(self, v1: client.CoreV1Api):
        """전체 파드 정보로 인덱스 갱신"""
        try:
            new_index = {}
            
            for namespace in self.target_namespaces:
                pods = v1.list_namespaced_pod(namespace=namespace)
                
                logging.info(f"\n=== {namespace} 네임스페이스 API 응답 ===")
                logging.info(f"조회된 파드 수: {len(pods.items)}")
                
                for pod in pods.items:
                    logging.info(f"\n파드 정보:")
                    logging.info(f"이름: {pod.metadata.name}")
                    logging.info(f"네임스페이스: {pod.metadata.namespace}")
                    logging.info(f"상태: {pod.status.phase}")
                    
                    if pod.status.container_statuses:
                        for container in pod.status.container_statuses:
                            if container.container_id:
                                container_hash = container.container_id.split('://')[-1]
                                logging.info(f"컨테이너 ID: {container.container_id}")
                                logging.info(f"컨테이너 해시: {container_hash}")
                                new_index[container_hash] = {
                                    'pod_name': pod.metadata.name,
                                    'namespace': pod.metadata.namespace,
                                    'container_name': container.name,
                                    'container_id': container.container_id,
                                    'pod_status': pod.status.phase,
                                    'updated_at': datetime.now()
                                }
            
            self.hash_to_pod = new_index
            logging.info(f"\n인덱스 업데이트 완료: {len(self.hash_to_pod)} 컨테이너 등록됨")
            logging.info("========================")
            
        except Exception as e:
            logging.error(f"Error updating index: {e}")

    def find_pods_by_partial_hash(self, partial_hash: str) -> List[dict]:
        """해시 일부값으로 파드 정보 검색"""
        if not partial_hash:
            return []
            
        return [
            {**pod_info, 'full_hash': full_hash}
            for full_hash, pod_info in self.hash_to_pod.items()
            if partial_hash in full_hash
        ]