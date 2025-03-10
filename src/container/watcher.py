from kubernetes_asyncio import client, config, watch
from .repository import ContainerHashRepository
from typing import List, Dict, Any
import asyncio
import logging

class AsyncPodWatcher:
    WATCH_TIMEOUT = 300  # 5분 타임아웃

    def __init__(self, namespace: str, repository: ContainerHashRepository, api: client.CoreV1Api):
        self.namespace = namespace
        self.repository = repository
        self.api = api
        self.logger = logging.getLogger(__name__)
        self._running = True
        self._last_resource_version = None
    
    async def stop(self):
        """워쳐 정지"""
        self._running = False
    
    async def start(self):
        """파드 모니터링 시작"""
        backoff = 1  # 초기 백오프 시간 (초)
        max_backoff = 60  # 최대 백오프 시간 (초)
        
        while self._running:
            try:
                # 리소스 버전 기반으로 목록 조회
                list_options = {}
                if self._last_resource_version is not None:
                    list_options['resource_version'] = self._last_resource_version
                
                # 초기 상태 동기화
                pods = await self.api.list_namespaced_pod(
                    self.namespace,
                    **list_options
                )
                self._sync_initial_state(pods.items)
                current_resource_version = pods.metadata.resource_version
                
                self.logger.info(
                    f"[동기화] {self.namespace} 네임스페이스 "
                    f"시작 버전: {self._last_resource_version or '최신'}, "
                    f"현재 버전: {current_resource_version}"
                )
                self.repository.print_current_state()

                # 워치 스트림 처리 (5분 타임아웃)
                async with watch.Watch() as w:
                    async for event in w.stream(
                        self.api.list_namespaced_pod,
                        namespace=self.namespace,
                        resource_version=current_resource_version,
                        timeout_seconds=self.WATCH_TIMEOUT
                    ):
                        if not self._running:
                            break
                            
                        # 이벤트의 리소스 버전 추적
                        new_version = event['object'].metadata.resource_version
                        self._last_resource_version = new_version
                        self._handle_pod_event(event)
                        backoff = 1  # 성공적인 처리 후 백오프 초기화
                
                # 타임아웃으로 인한 정상 종료 시
                self.logger.info(
                    f"[재연결] {self.namespace} 네임스페이스 워치 스트림 타임아웃"
                    f"(마지막 버전: {self._last_resource_version})"
                )
                continue  # 즉시 재연결
                
            except client.exceptions.ApiException as e:
                if e.status == 410:  # Gone - 리소스 버전 만료
                    self.logger.warning(
                        f"[재시도] 리소스 버전 만료로 최신 상태부터 다시 시작 "
                        f"(만료된 버전: {self._last_resource_version})"
                    )
                    self._last_resource_version = None  # 최신 상태부터 다시 시작
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
                    continue
                else:
                    self.logger.error(f"[오류] 쿠버네티스 API 오류: {e}")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
                    continue
                    
            except Exception as e:
                self.logger.error(f"[오류] 예상치 못한 오류 발생: {e}")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
                continue

        self.logger.info(f"[종료] {self.namespace} 네임스페이스 모니터링 종료")

    def _sync_initial_state(self, pods: List[Any]) -> None:
        """초기 파드 상태 동기화"""
        for pod in pods:
            self._sync_pod_container_state(pod)
    
    def _handle_pod_event(self, event: Dict[str, Any]) -> None:
        """파드 이벤트 처리""" 
        event_type = event['type']
        pod = event['object']
        
        self.logger.info(f"[이벤트] {self.namespace}/{pod.metadata.name} - {event_type}")
        
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