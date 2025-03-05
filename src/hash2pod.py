from kubernetes import client, config
import logging
from datetime import datetime
from typing import Dict, List
import time

class PodHashIndex:
    def __init__(self):
        self.hash_to_pod: Dict[str, dict] = {}

    def update_index(self, v1: client.CoreV1Api):
        """전체 파드 정보로 인덱스 갱신"""
        try:
            new_index = {}
            pods = v1.list_pod_for_all_namespaces()
            
            for pod in pods.items:
                if pod.status.container_statuses:
                    for container in pod.status.container_statuses:
                        if container.container_id:
                            container_hash = container.container_id.split('://')[-1]
                            new_index[container_hash] = {
                                'pod_name': pod.metadata.name,
                                'namespace': pod.metadata.namespace,
                                'container_name': container.name,
                                'container_id': container.container_id,
                                'pod_status': pod.status.phase,
                                'updated_at': datetime.now()
                            }
            
            self.hash_to_pod = new_index
            logging.info(f"Index updated with {len(self.hash_to_pod)} containers")
            
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

def main():
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    
    pod_index = PodHashIndex()
    
    while True:
        try:
            # 5분마다 인덱스 업데이트
            pod_index.update_index(v1)
            
            # 테스트용 부분 해시로 검색
            partial_hash = "95754b"
            results = pod_index.find_pods_by_partial_hash(partial_hash)
            
            if results:
                logging.info(f"\nFound {len(results)} matches for '{partial_hash}':")
                for pod in results:
                    logging.info(f"Pod: {pod['pod_name']}")
                    logging.info(f"Namespace: {pod['namespace']}")
                    logging.info(f"Container: {pod['container_name']}")
                    logging.info(f"Full Hash: {pod['full_hash']}")
            else:
                logging.info(f"\nNo pods found for hash: {partial_hash}")
            
            time.sleep(300)  # 5분 대기
            
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            time.sleep(5)

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    main()
