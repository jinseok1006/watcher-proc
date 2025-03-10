from typing import Optional

from .base import EventHandler
from ..api.client import APIClient
from ..events.models import EventBuilder
from ..process.types import ProcessType

class APIHandler(EventHandler[EventBuilder, EventBuilder]):
    """API 이벤트 핸들러
    
    완성된 이벤트를 API 서버로 전송합니다.
    이벤트 타입에 따라 적절한 엔드포인트로 전송됩니다.
    """
    
    def __init__(self):
        """초기화"""
        super().__init__()
        self.client = APIClient()
    
    async def handle(self, builder: EventBuilder) -> Optional[EventBuilder]:
        """이벤트 처리
        
        Args:
            builder: 이벤트 빌더 (모든 정보가 포함된 상태)
            
        Returns:
            EventBuilder 또는 None (API 전송 실패 시)
            
        Note:
            이벤트 타입에 따라 다른 엔드포인트로 전송:
            - 컴파일 이벤트: /api/:class_div/:hw_name/:student_id/logs/build
            - 실행 이벤트: /api/:class_div/:hw_name/:student_id/logs/run
        """
        try:
            # 필수 정보 검증
            if not builder.metadata or not builder.homework:
                self.logger.error("[전송 실패] 메타데이터 또는 과제 정보 누락")
                return None
                
            # 이벤트 전송
            success = False
            
            if builder.process.type in (ProcessType.GCC, ProcessType.CLANG):
                if not builder.homework.source_file:
                    self.logger.error("[전송 실패] 컴파일 이벤트에 소스 파일 정보 누락")
                    return None
                    
                success = await self.client.send_compilation(
                    event=builder.build(),
                    hw_dir=builder.homework.homework_dir,
                    source_file=builder.homework.source_file
                )
                
            else:  # 실행 이벤트
                success = await self.client.send_binary_execution(
                    event=builder.build(),
                    hw_dir=builder.homework.homework_dir
                )
            
            if not success:
                self.logger.error("[전송 실패] API 서버 응답 오류")
                return None
                
            return await self._handle_next(builder)
            
        except Exception as e:
            self.logger.error(f"[전송 실패] API 이벤트 처리 오류: {str(e)}")
            return None 