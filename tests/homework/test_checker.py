import pytest
from pathlib import Path
from unittest.mock import patch
from src.homework.checker import DefaultHomeworkChecker

class TestDefaultHomeworkChecker:
    @pytest.fixture
    def mock_settings(self):
        """테스트용 설정 모의 객체"""
        with patch('src.homework.checker.settings') as mock_settings:
            # 테스트용 기본 패턴 설정
            mock_settings.homework_path_pattern = r'^/(?:os|network|system)-\d+-\d+/hw\d+(?:/|$)'
            yield mock_settings

    @pytest.fixture
    def checker(self, mock_settings):
        """설정이 모의된 HomeworkChecker 인스턴스"""
        return DefaultHomeworkChecker()

    def test_valid_homework_paths(self, checker):
        """유효한 과제 경로 테스트"""
        valid_paths = [
            "/os-5-202012180/hw1/main.c",
            "/network-1-201912345/hw2/test",
            "/system-3-202154321/hw3"
        ]
        
        for path in valid_paths:
            result = checker.get_homework_info(path)
            hw_dir = path.split('/')[2]
            assert result == hw_dir, f"Failed for path: {path}"

    def test_invalid_paths(self, checker):
        """유효하지 않은 경로 테스트"""
        invalid_paths = [
            "/math-5-202012180/hw1/main.c",      # 허용되지 않은 과목
            "/os-a-202012180/hw1/main.c",        # 잘못된 분반 형식
            "/network-1-201912345/homework2",     # 잘못된 과제 디렉토리 형식
            "/system-3-202154321/hw3/hw4",       # 중첩된 과제 디렉토리
            "relative/path/hw1/main.c"           # 상대 경로
        ]
        
        for path in invalid_paths:
            result = checker.get_homework_info(path)
            assert result is None, f"Should fail for invalid path: {path}"

    def test_different_patterns(self, mock_settings):
        """다양한 패턴에 대한 테스트"""
        test_cases = [
            # (패턴, 테스트 경로, 기대 결과)
            (
                r'^/[a-z]+-\d+-\d+/hw\d+(?:/|$)',
                "/test-1-123456789/hw1/main.c",
                "hw1"
            ),
            (
                r'^/(?:os|network)-[1-5]-\d{9}/hw[1-9](?:/|$)',
                "/os-3-202012345/hw1/main.c",
                "hw1"
            ),
            (
                r'^/os-\d+-\d+/hw\d+(?:/|$)',
                "/network-1-123456789/hw1/main.c",
                None
            )
        ]
        
        for pattern, test_path, expected in test_cases:
            mock_settings.homework_path_pattern = pattern
            checker = DefaultHomeworkChecker()
            result = checker.get_homework_info(test_path)
            assert result == expected, f"Failed for pattern: {pattern}, path: {test_path}"

    def test_path_with_symlink(self, checker, tmp_path):
        """심볼릭 링크가 포함된 경로 테스트"""
        # 테스트용 디렉토리 구조 생성
        test_root = tmp_path / "test_root"
        base_dir = test_root / "os-5-202012180"
        hw1_dir = base_dir / "hw1"
        hw1_dir.mkdir(parents=True)
        
        source_file = hw1_dir / "main.c"
        source_file.touch()
        
        internal_link = hw1_dir / "link_to_main.c"
        internal_link.symlink_to(source_file)
        
        # 실제 경로를 테스트용 경로로 변환
        real_path = str(internal_link.resolve())
        test_path = real_path.replace(str(test_root), "")
        if not test_path.startswith('/'):
            test_path = '/' + test_path
        
        result = checker.get_homework_info(test_path)
        assert result == "hw1"

    def test_edge_cases(self, checker):
        """엣지 케이스 테스트"""
        edge_cases = [
            "",                                    # 빈 문자열
            "/",                                   # 루트 디렉토리
            "/os-5-202012180",                    # 과제 디렉토리 없음
            "/os-5-202012180/",                   # 과제 디렉토리 없음 (슬래시)
            None,                                  # None 입력
        ]
        
        for path in edge_cases:
            result = checker.get_homework_info(path)
            assert result is None, f"Should handle edge case: {path}"

    def test_nested_homework_paths(self, checker):
        """중첩된 과제 디렉토리 테스트"""
        nested_paths = [
            "/os-5-202012180/hw1/hw2/main.c",      # hw1 안의 hw2
            "/network-1-201912345/hw1/test/hw3",    # hw1 안의 hw3
            "/system-3-202154321/hw3/hw4"          # hw3 안의 hw4
        ]
        
        for path in nested_paths:
            result = checker.get_homework_info(path)
            assert result is None, f"Should fail for nested path: {path}" 