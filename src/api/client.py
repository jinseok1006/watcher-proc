import aiohttp
import logging
from typing import Dict, Any
from ..config.settings import settings
from ..events.models import Event

class APIClient:
    """API 클라이언트"""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_url = settings.api_endpoint.rstrip('/')

    async def _send_event(self, endpoint: str, data: Dict[str, Any]) -> bool:
        """이벤트 전송 공통 로직"""
        try:
            # 개발 환경에서는 실제 요청을 보내지 않고 로깅만 수행
            # async with aiohttp.ClientSession() as session:
            #     async with session.post(
            #         f'{self.base_url}{endpoint}',
            #         json=data,
            #         timeout=settings.api_timeout
            #     ) as response:
            #         if response.status >= 400:
            #             error_text = await response.text()
            #             self.logger.error(f"API 요청 실패: status={response.status}, response={error_text}")
            #             return False
            #         return True
            self.logger.info(f"API 요청 - endpoint: {endpoint}, data: {data}")
            return True
                    
        except Exception as e:
            self.logger.error(f"API 예상치 못한 오류: {str(e)}")
            return False

    async def send_binary_execution(self, event: Event) -> bool:
        """실행 이벤트 전송"""
        endpoint = f"/api/{event.metadata.class_div}/{event.homework.homework_dir}/{event.metadata.student_id}/logs/run"
        
        data = {
            'timestamp': event.metadata.timestamp.isoformat(),
            'exit_code': event.base.exit_code,
            'cmdline': event.base.args,
            'cwd': event.base.cwd,
            'binary_path': event.base.binary_path
        }
        return await self._send_event(endpoint, data)

    async def send_compilation(self, event: Event) -> bool:
        """컴파일 이벤트 전송"""
        endpoint = f"/api/{event.metadata.class_div}/{event.homework.homework_dir}/{event.metadata.student_id}/logs/build"
        
        data = {
            'timestamp': event.metadata.timestamp.isoformat(),
            'exit_code': event.base.exit_code,
            'cmdline': event.base.args,
            'cwd': event.base.cwd,
            'binary_path': event.base.binary_path
        }
        return await self._send_event(endpoint, data) 