import pytest
from pathlib import Path
from src.homework.checker import DefaultHomeworkChecker

@pytest.fixture
def project_structure(tmp_path):
    """테스트용 프로젝트 구조 생성"""
    # 과제 디렉토리 생성
    hw2_dir = tmp_path / "hw2"
    other_dir = tmp_path / "other"
    
    for dir_path in [hw2_dir, other_dir]:
        dir_path.mkdir()
        
    # 테스트 파일 생성
    (hw2_dir / "test.c").touch()
    (hw2_dir / "output").mkdir()
    (hw2_dir / "output" / "result.txt").touch()
    (other_dir / "temp.c").touch()
    
    return tmp_path

@pytest.fixture
def checker(project_structure):
    """HomeworkChecker 인스턴스 생성"""
    return DefaultHomeworkChecker(project_root=str(project_structure))

class TestDefaultHomeworkChecker:
    def test_valid_homework_path(self, checker, project_structure):
        """유효한 과제 경로 테스트"""
        test_file = project_structure / "hw1" / "main.c"
        result = checker.get_homework_info(str(test_file))
        
        assert result == "hw1"
        
    def test_nested_homework_path(self, checker, project_structure):
        """중첩된 과제 경로 테스트"""
        test_file = project_structure / "hw2" / "output" / "result.txt"
        result = checker.get_homework_info(str(test_file))
        
        assert result == "hw2"
        
    def test_non_homework_path(self, checker, project_structure):
        """과제가 아닌 경로 테스트"""
        test_file = project_structure / "other" / "temp.c"
        result = checker.get_homework_info(str(test_file))
        
        assert result is None
        
    def test_external_path(self, checker):
        """프로젝트 외부 경로 테스트"""
        test_file = "/usr/bin/gcc"
        result = checker.get_homework_info(test_file)
        
        assert result is None
        
    def test_invalid_path(self, checker):
        """잘못된 경로 테스트"""
        test_file = "non/existent/path/file.c"
        result = checker.get_homework_info(test_file)
        
        assert result is None
        
    def test_path_with_symlink(self, checker, project_structure):
        """심볼릭 링크가 포함된 경로 테스트"""
        # 1. 기본 디렉토리 구조 생성
        hw_dir = project_structure / "hw1"
        other_dir = project_structure / "other"
        hw_dir.mkdir(exist_ok=True)
        other_dir.mkdir(exist_ok=True)
        
        # 2. 원본 파일 생성 (hw1 디렉토리 내)
        source_file = hw_dir / "main.c"
        source_file.touch()
        
        # 3. 같은 디렉토리 내 심볼릭 링크 테스트
        internal_link = hw_dir / "link_to_main.c"
        internal_link.symlink_to(source_file)
        result_internal = checker.get_homework_info(str(internal_link))
        assert result_internal == "hw1"  # hw1 디렉토리 내부 링크
        
        # 4. 다른 디렉토리에서의 심볼릭 링크 테스트
        external_link = other_dir / "external_link.c"
        external_link.symlink_to(source_file)
        result_external = checker.get_homework_info(str(external_link))
        assert result_external == "hw1"  # 실제 파일이 hw1에 있으므로 hw1 반환
        
        # 5. 다른 과제 디렉토리에서의 심볼릭 링크 테스트
        hw2_dir = project_structure / "hw2"
        hw2_dir.mkdir(exist_ok=True)
        hw2_link = hw2_dir / "link_in_hw2.c"
        hw2_link.symlink_to(source_file)
        result_hw2 = checker.get_homework_info(str(hw2_link))
        assert result_hw2 == "hw1"  # 실제 파일이 hw1에 있으므로 hw1 반환
        
    def test_different_path_formats(self, checker, project_structure):
        """다양한 경로 형식 테스트"""
        # 테스트용 디렉토리 생성
        hw_dir = project_structure / "hw1"
        hw_dir.mkdir()
        (hw_dir / "main.c").touch()
        
        # 문자열 경로
        str_path = str(project_structure / "hw1" / "main.c")
        assert checker.get_homework_info(str_path) == "hw1"
        
        # Path 객체
        path_obj = project_structure / "hw1" / "main.c"
        assert checker.get_homework_info(path_obj) == "hw1"
        
        # 상대 경로 (현재 디렉토리 기준)
        relative_path = Path("./non-existent/hw1/main.c")
        result = checker.get_homework_info(relative_path)
        assert result is None  # 상대 경로는 None을 반환해야 함
            
    def test_case_sensitivity(self, checker, project_structure):
        """대소문자 구분 테스트 - 소문자 hw로 시작하는 디렉토리만 인식"""
        # HW1 디렉토리 생성 (대문자)
        hw_upper = project_structure / "HW1"
        hw_upper.mkdir()
        test_file = hw_upper / "test.c"
        test_file.touch()
        
        result = checker.get_homework_info(str(test_file))
        assert result is None  # 대문자로 된 과제 디렉토리는 인식하지 않아야 함
        
        # hw3 디렉토리 생성 (소문자, 다른 번호 사용)
        hw_lower = project_structure / "hw3"
        hw_lower.mkdir()
        test_file_lower = hw_lower / "test.c"
        test_file_lower.touch()
        
        result_lower = checker.get_homework_info(str(test_file_lower))
        assert result_lower == "hw3"  # 소문자로 된 과제 디렉토리는 인식해야 함

    def test_multiple_hw_directories(self, checker, project_structure):
        """중복 과제 디렉토리 구조 테스트"""
        # hw1/hw2 구조 생성
        nested_hw = project_structure / "hw1" / "hw2"
        nested_hw.mkdir(parents=True)
        test_file = nested_hw / "test.c"
        test_file.touch()
        
        result = checker.get_homework_info(str(test_file))
        assert result == "hw1"  # 최상위 과제 디렉토리를 반환해야 함 