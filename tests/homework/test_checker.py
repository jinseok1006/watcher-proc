import pytest
from pathlib import Path
from src.homework.checker import DefaultHomeworkChecker, HomeworkPath

class TestDefaultHomeworkChecker:
    @pytest.fixture
    def checker(self):
        """테스트용 HomeworkChecker 인스턴스"""
        return DefaultHomeworkChecker()

    def test_valid_homework_paths(self, checker):
        """유효한 과제 경로 테스트"""
        valid_paths = [
            "/os-5-202012180/hw1/main.c",          # 기본 경로
            "/network-1-201912345/hw20/test",      # hw20 (최대값)
            "/system-3-202154321/hw15",            # 디렉토리
            "/algorithm-2-202012345/hw1/src/main", # 중첩된 디렉토리
            "/database-1-201912345/hw2/",          # 끝에 슬래시
            "/os-99-202012345/hw1/main",          # 두 자리 분반
            "/network-1-1/hw1/test",              # 한 자리 학번
            "/os-1-123456789012/hw10/main",       # 12자리 학번 (허용)
        ]
        
        for path in valid_paths:
            result = checker.get_homework_info(path)
            hw_dir = path.split('/')[2]  # hw1, hw2 등
            assert result == hw_dir, f"Failed for path: {path}"

    def test_invalid_paths(self, checker):
        """유효하지 않은 경로 테스트"""
        invalid_paths = [
            # 형식 오류
            "/OS-5-202012180/hw1/main.c",      # 대문자 과목명
            "/os-a-202012180/hw1/main.c",      # 잘못된 분반 형식
            "/network-1-201912345/homework2",   # 잘못된 과제 디렉토리 형식
            "relative/path/hw1/main.c",         # 상대 경로
            "/os5-1-202012180/hw1",            # 잘못된 과목명 형식
            "/os--1-202012180/hw1",            # 잘못된 분반 형식 (음수)
            "/os-1-abc/hw1",                    # 잘못된 학번 형식 (문자)
            
            # 과제 번호 범위 테스트
            "/os-1-202012180/hw0/main",        # hw0 (불가)
            "/os-1-202012180/hw21/main",       # hw21 (불가)
            "/os-1-202012180/hw99/main",       # hw99 (불가)
            
            # 실제로 resolve 불가능한 경우만 invalid로 처리
            "/os-1-202012180/hw1/../../outside",  # 과제 디렉토리 밖으로 나가는 경우
            "~/os-1-202012180/hw1",              # 상대경로(~)
        ]
        
        for path in invalid_paths:
            result = checker.get_homework_info(path)
            assert result is None, f"Should fail for invalid path: {path}"

    def test_nested_homework_paths(self, checker):
        """중첩된 과제 디렉토리 테스트"""
        nested_paths = [
            "/os-5-202012180/hw1/hw2/main.c",      # hw1 안의 hw2
            "/network-1-201912345/hw1/test/hw3",    # hw1 안의 hw3
            "/system-3-202154321/hw3/hw4",         # hw3 안의 hw4
            "/os-5-202012180/hw1/src/hw1/main",    # 같은 이름의 중첩
            "/os-5-202012180/hw2/hw2",            # 동일 레벨 중첩
        ]
        
        for path in nested_paths:
            result = checker.get_homework_info(path)
            assert result is None, f"Should fail for nested path: {path}"

    def test_path_with_symlink(self, checker, tmp_path):
        """심볼릭 링크가 포함된 경로 테스트"""
        # 테스트용 디렉토리 구조 생성
        test_root = tmp_path / "test_root"
        base_dir = test_root / "os-5-202012180"
        hw1_dir = base_dir / "hw1"
        hw1_dir.mkdir(parents=True)
        
        # 파일 생성
        source_file = hw1_dir / "main.c"
        source_file.touch()
        
        # 다양한 심볼릭 링크 테스트
        test_cases = [
            (hw1_dir / "link_to_main.c", source_file),              # 같은 디렉토리 내 링크
            (base_dir / "link_to_hw1_main.c", source_file),        # 상위 디렉토리 링크
            (hw1_dir / "subdir" / "link_to_main.c", source_file),  # 하위 디렉토리 링크
        ]
        
        for link_path, target in test_cases:
            # 링크 생성을 위한 디렉토리 준비
            link_path.parent.mkdir(parents=True, exist_ok=True)
            link_path.symlink_to(target)
            
            # 실제 경로를 테스트용 경로로 변환
            real_path = str(link_path.resolve())
            test_path = real_path.replace(str(test_root), "")
            if not test_path.startswith('/'):
                test_path = '/' + test_path
            
            result = checker.get_homework_info(test_path)
            assert result == "hw1", f"Failed for symlink: {test_path}"

    def test_edge_cases(self, checker):
        """엣지 케이스 테스트"""
        edge_cases = [
            # 빈 입력
            "",                                     # 빈 문자열
            None,                                   # None 입력
            
            # 최소 길이 경로
            "/os-1-202012180",                     # 과제 디렉토리 없음
            "/os-1-202012180/",                    # 과제 디렉토리 없음 (슬래시)
            
            # 특수 문자와 공백
            "/os 1-202012180/hw1",                 # 과목명에 공백
            "/os-1 -202012180/hw1",               # 분반에 공백
            "/os-1-202012180/hw 1",               # 과제 번호에 공백
            
            # 파일 시스템 특수 경로
            "/",                                    # 루트 디렉토리
            ".",                                    # 현재 디렉토리
            "..",                                   # 상위 디렉토리
            "~/os-1-202012180/hw1",               # 홈 디렉토리
            
            # 이스케이프 문자
            "/os-1-202012180/hw1/\n",             # 줄바꿈
            "/os-1-202012180/hw1/\t",             # 탭
            "/os-1-202012180/hw1/\r",             # 캐리지 리턴
        ]
        
        for path in edge_cases:
            result = checker.get_homework_info(path)
            assert result is None, f"Should handle edge case: {path}"

    def test_valid_paths_with_unicode(self, checker):
        """유니코드를 포함한 유효한 경로 테스트"""
        valid_paths = [
            # 기본 경로
            "/os-0-202012180/hw1/main.c",          # 0분반 허용
            "/o-1-1/hw1/main",                     # 최소 길이 컴포넌트 허용
            
            # 유니코드 경로
            "/os-1-202012180/hw1/한글파일.c",      # 한글 파일명
            "/os-1-202012180/hw1/테스트/main.c",   # 한글 디렉토리
            "/os-1-202012180/hw1/🔥.c",           # 이모지
            "/os-1-202012180/hw1/테스트.txt",      # 한글 확장자
        ]
        
        for path in valid_paths:
            result = checker.get_homework_info(path)
            hw_dir = path.split('/')[2]  # hw1, hw2 등
            assert result == hw_dir, f"Should succeed for valid path: {path}"

    def test_valid_paths_with_special_cases(self, checker):
        """특수 케이스를 포함한 유효한 경로 테스트"""
        valid_paths = [
            # resolve 가능한 경로들
            "/os-1-202012180/hw1/./main",        # 현재 디렉토리
            "/os-1-202012180/hw1/foo/../main",   # 상위 디렉토리 (같은 과제 내)
            "/os-1-202012180/hw1//main",         # 중복 슬래시

            # 분반 번호 테스트
            "/os-0-202012180/hw1/main.c",          # 0분반 허용
            "/os-99-202012180/hw1/main",           # 2자리 분반
            "/os-100-202012180/hw1/main",          # 3자리 분반
            
            # 공백 관련 테스트
            "/os-1-202012180/hw1/hello world.c",   # 중간 공백
            "/os-1-202012180/hw1/hello.txt ",      # 끝 공백
            "/os-1-202012180/hw1/ ",               # 공백 파일명
            "/os-1-202012180/hw1/",                # 슬래시로 끝나는 경로
            
            # 과제 번호 테스트
            "/os-1-123456789/hw10/main",           # hw10
            "/os-1-123456789/hw20/main",           # hw20 (최대값)
        ]
        
        for path in valid_paths:
            result = checker.get_homework_info(path)
            hw_dir = path.split('/')[2]
            assert result == hw_dir, f"Should succeed for valid path: {path}" 