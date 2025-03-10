import re
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
from .base import HomeworkChecker
from ..utils.logging import get_logger

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
        self.logger = get_logger(__name__)
        # 프로덕션 환경에서는 반드시 아래 패턴을 사용해야 함
        # 학생 컨테이너의 경로 구조: /{subject}-{section}-{student_id}/hw{n}/...
        self.pattern = re.compile(
            f'^/({self.SUBJECT})-({self.SECTION})-({self.STUDENT_ID})/'
            f'({self.HOMEWORK})({self.SUB_PATH})?$'
        )
        # 개발/테스트 환경에서는 아래 패턴 사용 가능
        # self.pattern = re.compile(
        #     f'.*/({self.SUBJECT})-({self.SECTION})-({self.STUDENT_ID})/'
        #     f'({self.HOMEWORK})({self.SUB_PATH})?$'
        # )
        self.logger.info("[HomeworkChecker] 초기화 완료")

    def get_homework_info(self, path: str) -> str | None:
        """과제 경로에서 과제 디렉토리명 추출"""
        try:
            result = self._validate(path)
            return result.homework_dir if result else None
        except Exception as e:
            self.logger.error(f"[HomeworkChecker] 경로 검사 실패 - 파일: {path}, 오류: {e}")
            return None

    def _validate(self, path: str | Path) -> Optional[HomeworkPath]:
        """경로 검증 및 파싱"""
        try:
            if path is None:
                self.logger.debug("[HomeworkChecker] 검증 실패 - 경로가 None입니다")
                return None

            # 이스케이프 문자 거부
            if any(c in str(path) for c in ['\n', '\t', '\r']):
                self.logger.debug(f"[HomeworkChecker] 검증 실패 - 경로에 이스케이프 문자가 포함되어 있습니다: {path}")
                return None

            # 경로 정규화
            try:
                normalized_path = os.path.normpath(str(path))
            except Exception as e:
                self.logger.debug(f"[HomeworkChecker] 검증 실패 - 경로 정규화 실패: {path}, 오류: {e}")
                return None

            # 상대 경로 거부
            if not normalized_path.startswith('/'):
                self.logger.debug(f"[HomeworkChecker] 검증 실패 - 상대 경로는 지원하지 않습니다: {normalized_path}")
                return None

            # 중첩된 hw 디렉토리 체크
            parts = normalized_path.split('/')
            hw_count = sum(1 for part in parts if part.startswith('hw'))
            if hw_count > 1:
                self.logger.debug(f"[HomeworkChecker] 검증 실패 - 중첩된 hw 디렉토리가 있습니다: {normalized_path}")
                return None

            # 정규화된 경로로 패턴 매칭
            match = self.pattern.match(normalized_path)
            if not match:
                self.logger.debug(f"[HomeworkChecker] 검증 실패 - 경로 패턴이 일치하지 않습니다: {normalized_path}")
                return None

            # 결과 파싱
            subject, section, student_id, hw_dir = match.groups()[:4]
            sub_path = match.group(5)

            result = HomeworkPath(
                subject=subject,
                section=int(section),
                student_id=student_id,
                homework_number=int(hw_dir[2:]),  # 'hw1' -> 1
                sub_path=sub_path
            )
            self.logger.debug(f"[HomeworkChecker] 검증 성공 - 경로: {normalized_path}, 결과: {result}")
            return result

        except (TypeError, AttributeError, ValueError) as e:
            self.logger.debug(f"[HomeworkChecker] 검증 실패 - 파싱 중 오류 발생: {path}, 오류: {e}")
            return None 