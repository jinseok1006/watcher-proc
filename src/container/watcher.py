from kubernetes_asyncio import client, config, watch
from .repository import ContainerHashRepository
from typing import List, Dict, Any
import asyncio

class AsyncPodWatcher:
    def __init__(self, namespace: str, repository: ContainerHashRepository, api: client.CoreV1Api):
        self.namespace = namespace
        self.repository = repository
        self.api = api
    
    async def start(self):
        """파드 모니터링 시작"""
        try:
            # 초기 상태 동기화 (API 호출은 비동기)
            pods = await self.api.list_namespaced_pod(self.namespace)
            self._sync_initial_state(pods.items)
            
            print(f"\n시작 리소스 버전: {pods.metadata.resource_version}")
            print(f"{self.namespace} 네임스페이스 모니터링 시작...")
            # self.repository.print_current_state()

            # 비동기 Watch 스트림 처리
            async with watch.Watch() as w:
                async for event in w.stream(self.api.list_namespaced_pod, 
                                          namespace=self.namespace,
                                          resource_version=pods.metadata.resource_version):
                    self._handle_pod_event(event)
                
        except client.exceptions.ApiException as e:
            print(f"쿠버네티스 API 오류: {e}")

    def _sync_initial_state(self, pods: List[Any]) -> None:
        """초기 파드 상태 동기화"""
        for pod in pods:
            self._sync_pod_container_state(pod)
    
    def _handle_pod_event(self, event: Dict[str, Any]) -> None:
        """파드 이벤트 처리""" 
        event_type = event['type']
        pod = event['object']
        
        print(f"\n이벤트 발생: {event_type} - {pod.metadata.name}")
        
        if event_type in ['ADDED', 'MODIFIED']:
            self._sync_pod_container_state(pod)
        elif event_type == 'DELETED':
            self.repository.remove_pod_containers(
                pod_name=pod.metadata.name,
                namespace=pod.metadata.namespace
            )
    
    def _sync_pod_container_state(self, pod: Any) -> None:
        """파드의 컨테이너 상태 동기화"""
        namespace = pod.metadata.namespace
        pod_name = pod.metadata.name
        
        # 현재 파드의 모든 컨테이너 해시 수집
        container_hashes = set()
        container_details = {}
        
        if pod.status.container_statuses:
            for container in pod.status.container_statuses:
                if container.container_id:
                    container_hash = self._extract_container_hash(container.container_id)[:12]
                    container_hashes.add(container_hash)
                    container_details[container_hash] = {
                        'name': container.name,
                        'state': str(container.state),
                        'ready': container.ready
                    }
        
        # 파드 정보 구성
        pod_info = {
            'namespace': namespace,
            'pod_name': pod_name,
            'phase': pod.status.phase,
            'containers': container_details
        }
        
        # 저장소 업데이트
        self.repository.save_pod_containers(
            namespace=namespace,
            pod_name=pod_name,
            container_hashes=container_hashes,
            pod_info=pod_info
        )
    
    @staticmethod
    def _extract_container_hash(container_id: str) -> str:
        """컨테이너 ID에서 해시 추출"""
        return container_id.split('://')[-1]