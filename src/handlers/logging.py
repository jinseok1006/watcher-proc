"""이벤트 로깅 핸들러

API 전송 전에 이벤트의 최종 상태를 로깅합니다.
"""

from typing import Optional
from .base import EventHandler
from ..events.models import EventBuilder

class LoggingHandler(EventHandler[EventBuilder, EventBuilder]):
    """이벤트 로깅 핸들러
    
    API 전송 전에 이벤트의 최종 상태를 로깅합니다.
    이벤트 파싱이 정상적으로 완료되었는지 확인하는 용도로 사용됩니다.
    """
    
    async def handle(self, builder: EventBuilder) -> Optional[EventBuilder]:
        """이벤트 처리
        
        Args:
            builder: 이벤트 빌더 (모든 정보가 포함된 상태)
            
        Returns:
            EventBuilder: 다음 핸들러로 전달할 이벤트 빌더
        """
        try:
            # 이벤트 빌드 (최종 상태 확인)
            event = builder.build()
            
            # 기본 정보 로깅
            self.logger.info(
                f"\n=== 이벤트 파싱 완료 ===\n"
                f"호스트: {event.base.hostname}\n"
                f"PID: {event.base.pid}\n"
                f"프로세스: {event.process.type.name}\n"
                f"실행 파일: {event.base.binary_path}\n"
                f"작업 디렉토리: {event.base.cwd}\n"
                f"명령줄: {event.base.args}\n"
                f"종료 코드: {event.base.exit_code}\n"
                f"에러 플래그: {event.base.error_flags}"
            )
            
            # 메타데이터 로깅
            if event.metadata:
                self.logger.info(
                    f"\n=== 메타데이터 ===\n"
                    f"분반: {event.metadata.class_div}\n"
                    f"학번: {event.metadata.student_id}\n"
                    f"타임스탬프: {event.metadata.timestamp}"
                )
            
            # 과제 정보 로깅
            if event.homework:
                self.logger.info(
                    f"\n=== 과제 정보 ===\n"
                    f"과제 디렉토리: {event.homework.homework_dir}\n"
                    f"소스 파일: {event.homework.source_file or '없음'}"
                )
            
            return await self._handle_next(builder)
            
        except Exception as e:
            self.logger.error(f"[로깅 실패] 이벤트 로깅 중 오류 발생: {str(e)}")
            return None 