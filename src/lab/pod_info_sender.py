from datetime import datetime
import re
import logging
import aiohttp
from typing import Optional, Dict
from .config.settings import Settings

class PodInfoParser:
    def __init__(self):
        # jcode-os-5-2020123456 형식 파싱
        self.pattern = re.compile(r'jcode-([a-zA-Z]+-\d+)-(\d+)')

    def parse_pod_name(self, pod_name: str) -> Optional[Dict[str, str]]:
        """파드 이름에서 정보 파싱
        예: jcode-os-5-2020123456 -> 
        {
            'class_div': 'os-5',
            'student_id': '2020123456'
        }
        """
        try:
            match = self.pattern.match(pod_name)
            if match:
                return {
                    'class_div': match.group(1),
                    'student_id': match.group(2)
                }
            return None
        except Exception as e:
            logging.error(f"파드 이름 파싱 실패: {pod_name}, 에러: {e}")
            return None

class BuildLogSender:
    def __init__(self):
        self.parser = PodInfoParser()
        self.base_url = Settings.get_api_endpoint()
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {Settings.get_api_token()}'
        }

    async def send_build_log(self, 
                           pod_info: dict, 
                           exit_code: int,
                           hw_name: str,
                           build_files: Optional[Dict[str, str]] = None) -> bool:
        """빌드 로그 전송
        
        Args:
            pod_info: 파드 정보
            exit_code: 종료 코드
            hw_name: 과제명
            build_files: {
                'source': '소스파일명',
                'output': '출력파일명'
            }
        """
        parsed_info = self.parser.parse_pod_name(pod_info['pod_name'])
        if not parsed_info:
            return False

        # API 엔드포인트 구성
        endpoint = f"{self.base_url}/api/{parsed_info['class_div']}/{hw_name}/{parsed_info['student_id']}/logs/build"

        payload = {
            'timestamp': datetime.now().isoformat(),
            'exit_code': exit_code,
            'container_id': pod_info['container_id']
        }

        # 빌드 파일 정보가 있는 경우 추가
        if build_files:
            payload.update(build_files)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    json=payload,
                    headers=self.headers
                ) as response:
                    if response.status == 200:
                        logging.info(f"빌드 로그 전송 성공: {pod_info['pod_name']}")
                        return True
                    else:
                        logging.error(f"빌드 로그 전송 실패: {response.status}, {await response.text()}")
                        return False
        except Exception as e:
            logging.error(f"빌드 로그 전송 중 에러 발생: {e}")
            return False 