from typing import Optional

from .base import EventHandler
from ..events.models import EventBuilder, ProcessTypeInfo
from ..process.filter import ProcessFilter
from ..process.types import ProcessType

class ProcessTypeHandler(EventHandler[EventBuilder, EventBuilder]):
    """프로세스 타입 감지 핸들러
    
    실행된 프로세스의 타입을 감지하여 이벤트에 추가합니다.
    """
    
    def __init__(self, process_filter: ProcessFilter):
        """초기화
        
        Args:
            process_filter: 프로세스 타입 결정을 위한 필터
        """
        super().__init__()
        self.process_filter = process_filter
    
    async def handle(self, builder: EventBuilder) -> Optional[EventBuilder]:
        """이벤트 처리
        
        Args:
            builder: 이벤트 빌더
            
        Returns:
            처리된 이벤트 빌더 또는 None
        """
        try:
            self.logger.info(f"[ProcessTypeHandler] 프로세스 타입 감지 시작 - PID: {builder.base.pid}")
            
            # 프로세스 타입 감지
            process_type = self.process_filter.get_process_type(builder.base.binary_path)
            if process_type == ProcessType.UNKNOWN:
                self.logger.info(f"[ProcessTypeHandler] 알 수 없는 프로세스 타입 - PID: {builder.base.pid}, 실행 파일: {builder.base.binary_path}")
                return None
                
            # 프로세스 정보 설정
            builder.process = ProcessTypeInfo(type=process_type)
            self.logger.info(f"[ProcessTypeHandler] 프로세스 타입 감지 완료 - PID: {builder.base.pid}, 타입: {process_type.name}")
            
            return await self._handle_next(builder)
            
        except Exception as e:
            self.logger.error(f"[ProcessTypeHandler] 프로세스 타입 감지 실패 - PID: {builder.base.pid}, 오류: {str(e)}")
            raise 