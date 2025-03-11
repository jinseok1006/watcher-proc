import pytest
from pathlib import Path
from src.homework.checker import HomeworkChecker

class TestHomeworkChecker:
    @pytest.fixture
    def checker(self):
        """테스트용 HomeworkChecker 인스턴스"""
        return HomeworkChecker()

    def test_valid_homework_paths(self, checker):
        """유효한 과제 경로 테스트"""
        valid_paths = [
            # 학생 볼륨 경로
            "/os-5-202012180/hw1/main.c",          # 기본 경로
            "/network-1-201912345/hw20/test",      # hw20 (최대값)
            "/system-3-202154321/hw15",            # 디렉토리
            "/algorithm-2-202012345/hw1/src/main", # 중첩된 디렉토리
            "/database-1-201912345/hw2/",          # 끝에 슬래시
            "/os-99-202012345/hw1/main",          # 두 자리 분반
            "/network-1-1/hw1/test",              # 한 자리 학번
            "/os-1-123456789012/hw10/main",       # 12자리 학번

            # 프로젝트 경로
            "/home/coder/project/hw1/main.c",      # 기본 경로
            "/home/coder/project/hw20/test",       # hw20 (최대값)
            "/home/coder/project/hw15",            # 디렉토리
            "/home/coder/project/hw1/src/main",    # 중첩된 디렉토리
            "/home/coder/project/hw2/",            # 끝에 슬래시
        ]
        
        for path in valid_paths:
            result = checker.get_homework_info(path)
            hw_dir = path.split('/')[4] if path.startswith('/home/coder/project/') else path.split('/')[2]
            assert result == hw_dir, f"Failed for path: {path}"

    def test_invalid_paths(self, checker):
        """유효하지 않은 경로 테스트"""
        invalid_paths = [
            # 형식 오류 - 학생 볼륨 경로
            "/OS-5-202012180/hw1/main.c",      # 대문자 과목명
            "/os-a-202012180/hw1/main.c",      # 잘못된 분반 형식
            "/network-1-201912345/homework2",   # 잘못된 과제 디렉토리 형식
            "relative/path/hw1/main.c",         # 상대 경로
            "/os5-1-202012180/hw1",            # 잘못된 과목명 형식
            "/os--1-202012180/hw1",            # 잘못된 분반 형식 (음수)
            "/os-1-abc/hw1",                    # 잘못된 학번 형식 (문자)
            
            # 형식 오류 - 프로젝트 경로
            "/home/coder/projects/hw1/main.c",  # 잘못된 프로젝트 경로
            "/home/user/project/hw1/main.c",    # 잘못된 사용자 경로
            "/project/hw1/main.c",              # 잘못된 경로 구조
            
            # 과제 번호 범위 테스트
            "/os-1-202012180/hw0/main",        # hw0 (불가)
            "/os-1-202012180/hw21/main",       # hw21 (불가)
            "/os-1-202012180/hw99/main",       # hw99 (불가)
            "/home/coder/project/hw0/main",     # hw0 (불가)
            "/home/coder/project/hw21/main",    # hw21 (불가)
            
            # 실제로 resolve 불가능한 경우
            "/os-1-202012180/hw1/../../outside",  # 과제 디렉토리 밖으로 나가는 경우
            "~/os-1-202012180/hw1",              # 상대경로(~)
        ]
        
        for path in invalid_paths:
            result = checker.get_homework_info(path)
            assert result is None, f"Should fail for invalid path: {path}"

    def test_nested_homework_paths(self, checker):
        """중첩된 과제 디렉토리 테스트"""
        nested_paths = [
            # 학생 볼륨 경로
            "/os-5-202012180/hw1/hw2/main.c",      # hw1 안의 hw2
            "/network-1-201912345/hw1/test/hw3",    # hw1 안의 hw3
            
            # 프로젝트 경로
            "/home/coder/project/hw1/hw2/main.c",   # hw1 안의 hw2
            "/home/coder/project/hw1/src/hw1/main", # 같은 이름의 중첩
        ]
        
        for path in nested_paths:
            result = checker.get_homework_info(path)
            assert result is None, f"Should fail for nested path: {path}"

    def test_edge_cases(self, checker):
        """엣지 케이스 테스트"""
        edge_cases = [
            # 빈 입력
            "",                                     # 빈 문자열
            None,                                   # None 입력
            
            # 최소 길이 경로
            "/os-1-202012180",                     # 과제 디렉토리 없음
            "/os-1-202012180/",                    # 과제 디렉토리 없음 (슬래시)
            "/home/coder/project",                 # 과제 디렉토리 없음
            "/home/coder/project/",                # 과제 디렉토리 없음 (슬래시)
            
            # 특수 문자와 공백
            "/os 1-202012180/hw1",                 # 과목명에 공백
            "/os-1 -202012180/hw1",               # 분반에 공백
            "/os-1-202012180/hw 1",               # 과제 번호에 공백
            "/home/coder/project/hw 1",           # 과제 번호에 공백
            
            # 이스케이프 문자
            "/os-1-202012180/hw1/\n",             # 줄바꿈
            "/os-1-202012180/hw1/\t",             # 탭
            "/os-1-202012180/hw1/\r",             # 캐리지 리턴
            "/home/coder/project/hw1/\n",         # 줄바꿈
        ]
        
        for path in edge_cases:
            result = checker.get_homework_info(path)
            assert result is None, f"Should handle edge case: {path}"

    def test_path_normalization(self, checker):
        """경로 정규화 테스트"""
        paths = [
            # 중복 슬래시 제거
            ("/os-1-202012180//hw1/main.c", "hw1"),
            ("/home/coder/project//hw1/main.c", "hw1"),
            
            # 현재 디렉토리(.) 처리
            ("/os-1-202012180/./hw1/main.c", "hw1"),
            ("/home/coder/project/./hw1/main.c", "hw1"),
            
            # 상위 디렉토리(..) 처리 (과제 디렉토리 내에서만)
            ("/os-1-202012180/hw1/test/../main.c", "hw1"),
            ("/home/coder/project/hw1/test/../main.c", "hw1"),
        ]
        
        for path, expected in paths:
            result = checker.get_homework_info(path)
            assert result == expected, f"Failed for path: {path}" 