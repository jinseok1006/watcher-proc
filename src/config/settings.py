from typing import List
import os

class Settings:
    # 기본 네임스페이스 설정
    DEFAULT_NAMESPACES: List[str] = [
        "jcode-os-5",
        "jcode-ai-4"
    ]

    @classmethod
    def get_target_namespaces(cls) -> List[str]:
        """
        환경 변수나 기본값에서 대상 네임스페이스 목록을 가져옴
        환경변수 설정 예: TARGET_K8S_NAMESPACES=jcode-os-5,jcode-ai-4
        """
        env_namespaces = os.getenv('TARGET_K8S_NAMESPACES')
        if env_namespaces:
            return env_namespaces.split(',')
        return cls.DEFAULT_NAMESPACES

    # 추후 다른 설정들도 추가 가능
    UPDATE_INTERVAL: int = int(os.getenv('INDEX_UPDATE_INTERVAL', '300'))  # 기본 5분 

    @classmethod
    def get_api_endpoint(cls) -> str:
        """API 엔드포인트 설정"""
        return os.getenv('BUILD_LOG_API_ENDPOINT', 'http://api-server')

    @classmethod
    def get_api_token(cls) -> str:
        """API 인증 토큰"""
        return os.getenv('BUILD_LOG_API_TOKEN', '')

    # 과제 정보 매핑 (필요한 경우)
    ASSIGNMENT_MAP = {
        'gcc': 'assignment1',
        'g++': 'assignment2',
        # ... 다른 매핑 정보
    } 