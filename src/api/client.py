import aiohttp
import logging
from typing import Dict, Any
from ..config.settings import settings
from ..events.models import EventBuilder

class APIClient:
    """API 클라이언트"""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_url = settings.api_endpoint.rstrip('/')

    async def _send_event(self, endpoint: str, data: Dict[str, Any]) -> bool:
        """이벤트 전송 공통 로직"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'{self.base_url}{endpoint}',
                    json=data,
                    timeout=settings.api_timeout
                ) as response:
                    if response.status >= 400:
                        error_text = await response.text()
                        self.logger.error(
                            f"[API 오류] 이벤트 전송 실패: "
                            f"상태 코드={response.status}, "
                            f"응답={error_text}, "
                            f"데이터={data}"
                        )
                        return False
                    
                    self.logger.info(f"[API 성공] {endpoint} 이벤트 전송 완료")
                    return True
                    
        except aiohttp.ClientError as e:
            self.logger.error(f"[API 오류] 네트워크 오류: {str(e)}, 데이터={data}")
            return False
        except Exception as e:
            self.logger.error(f"[API 오류] 예상치 못한 오류: {str(e)}, 데이터={data}")
            return False

    async def send_binary_execution(self, event: EventBuilder, hw_dir: str) -> bool:
        """바이너리 실행 이벤트 전송"""
        # URL 패턴: /api/:class_div/:hw_name/:student_id/logs/run
        endpoint = f"/api/{event.metadata.student.class_div}/{hw_dir}/{event.metadata.student.student_id}/logs/run"
        
        data = {
            'pod_name': event.base.hostname,
            'container_id': "unknown",  # TODO: 컨테이너 ID 추가
            'pid': event.base.pid,
            'binary_path': event.base.binary_path,
            'working_dir': event.base.cwd,
            'command_line': event.base.command,
            'exit_code': 0,  # TODO: 종료 코드 추가
            'error_flags': [],  # TODO: 에러 플래그 추가
            'timestamp': event.metadata.timestamp.isoformat()
        }
        return await self._send_event(endpoint, data)

    async def send_compilation(self, 
                             event: EventBuilder, 
                             hw_dir: str,
                             source_file: str) -> bool:
        """컴파일 이벤트 전송"""
        # URL 패턴: /api/:class_div/:hw_name/:student_id/logs/build
        endpoint = f"/api/{event.metadata.student.class_div}/{hw_dir}/{event.metadata.student.student_id}/logs/build"
        
        data = {
            'pod_name': event.base.hostname,
            'container_id': "unknown",  # TODO: 컨테이너 ID 추가
            'pid': event.base.pid,
            'source_file': source_file,
            'compiler_path': event.base.binary_path,
            'working_dir': event.base.cwd,
            'command_line': event.base.command,
            'exit_code': 0,  # TODO: 종료 코드 추가
            'error_flags': [],  # TODO: 에러 플래그 추가
            'timestamp': event.metadata.timestamp.isoformat()
        }
        return await self._send_event(endpoint, data) 