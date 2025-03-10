"""메타데이터 보강 핸들러

이벤트에 메타데이터(타임스탬프, 분반, 학번 등)를 추가합니다.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from .base import EventHandler
from ..events.models import EventBuilder, EventMetadata
from ..utils.logging import get_logger

class EnrichmentHandler(EventHandler[EventBuilder, EventBuilder]):
    """메타데이터 보강 핸들러"""
    
    def __init__(self):
        super().__init__()
        self.logger = get_logger(__name__)
        self._hostname_pattern = re.compile(
            r"jcode-(?P<class_div>[\w-]+)-(?P<student_id>\d+)-\w+"
        )
        
    async def handle(self, builder: EventBuilder) -> Optional[EventBuilder]:
        """이벤트 처리
        
        Args:
            builder: 이벤트 빌더
            
        Returns:
            처리된 이벤트 빌더 또는 None
        """
        try:
            self.logger.info("메타데이터 보강 시작")
            
            # 호스트네임에서 정보 추출
            match = self._hostname_pattern.match(builder.base.hostname)
            if not match:
                self.logger.warning(f"호스트네임 패턴 불일치 - 호스트네임: {builder.base.hostname}")
                return None
                
            # 메타데이터 설정
            builder.metadata = EventMetadata(
                class_div=match.group("class_div"),
                student_id=match.group("student_id"),
                timestamp=datetime.now(timezone.utc)
            )
            
            self.logger.info(
                f"메타데이터 보강 완료 - "
                f"분반: {builder.metadata.class_div}, "
                f"학번: {builder.metadata.student_id}"
            )
            
            return await self._handle_next(builder)
            
        except Exception as e:
            self.logger.error(f"메타데이터 보강 실패 - 오류: {str(e)}")
            raise 