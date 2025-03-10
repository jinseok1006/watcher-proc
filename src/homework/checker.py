import logging
import re
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
from .base import HomeworkChecker

@dataclass(frozen=True)
class HomeworkPath:
    """파싱된 과제 경로 정보"""
    subject: str
    section: int
    student_id: str
    homework_number: int
    sub_path: Optional[str] = None

    @property
    def homework_dir(self) -> str:
        """과제 디렉토리명 반환"""
        return f"hw{self.homework_number}"

class DefaultHomeworkChecker(HomeworkChecker):
    """과제 디렉토리 체커 구현"""
    # 경로 패턴 상수
    SUBJECT = r'[a-z]+'                    # 과목명: 영문 소문자만
    SECTION = r'\d+'                       # 분반: 숫자
    STUDENT_ID = r'\d+'                    # 학번: 숫자
    HOMEWORK = r'hw(?:[1-9]|1[0-9]|20)'   # 과제 번호: hw1-hw20
    SUB_PATH = r'/[^/].*'                  # 서브 경로: 슬래시로 시작하고 비어있지 않은 경로

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.pattern = re.compile(
            f'^/({self.SUBJECT})-({self.SECTION})-({self.STUDENT_ID})/'
            f'({self.HOMEWORK})({self.SUB_PATH})?$'
        )
        self.logger.info("[초기화] 과제 체커 초기화 완료")

    def get_homework_info(self, path: str) -> str | None:
        """과제 경로에서 과제 디렉토리명 추출"""
        try:
            result = self._validate(path)
            return result.homework_dir if result else None
        except Exception as e:
            self.logger.error(f"[경로 검사 실패] 파일: {path}, 오류: {e}")
            return None

    def _validate(self, path: str | Path) -> Optional[HomeworkPath]:
        """경로 검증 및 파싱"""
        try:
            if path is None:
                return None

            # 이스케이프 문자 거부
            if any(c in str(path) for c in ['\n', '\t', '\r']):
                return None

            # 경로 정규화
            try:
                normalized_path = os.path.normpath(str(path))
            except Exception:
                return None

            # 상대 경로 거부
            if not normalized_path.startswith('/'):
                return None

            # 중첩된 hw 디렉토리 체크
            parts = normalized_path.split('/')
            hw_count = sum(1 for part in parts if part.startswith('hw'))
            if hw_count > 1:
                return None

            # 정규화된 경로로 패턴 매칭
            match = self.pattern.match(normalized_path)
            if not match:
                return None

            # 결과 파싱
            subject, section, student_id, hw_dir = match.groups()[:4]
            sub_path = match.group(5)

            return HomeworkPath(
                subject=subject,
                section=int(section),
                student_id=student_id,
                homework_number=int(hw_dir[2:]),  # 'hw1' -> 1
                sub_path=sub_path
            )

        except (TypeError, AttributeError, ValueError):
            return None 