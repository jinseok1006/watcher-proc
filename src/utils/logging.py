import logging
from ..config.settings import settings

def setup_logging():
    """기본 로깅 설정
    
    settings 객체에서 로깅 설정을 가져와 적용합니다.
    """
    logging.basicConfig(
        level=settings.log_level_enum,
        format=settings.log_format
    )
    
    logger = logging.getLogger(__name__)
    logger.debug("[설정] 로깅 설정 완료 (레벨: %s)", settings.log_level) 