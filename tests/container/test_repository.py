import pytest
from src.container.repository import ContainerHashRepository

@pytest.fixture
def repo():
    """테스트에서 사용할 저장소 인스턴스"""
    return ContainerHashRepository()

def test_save_and_find_container(repo):
    """컨테이너 저장 및 조회 테스트"""
    # Given
    namespace = "test-ns"
    pod_name = "test-pod"
    container_hash = "abcdef123456"  # 정확히 12자리
    container_hashes = {container_hash}
    
    pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Running',
        'containers': {
            container_hash: {
                'name': 'test-container',
                'state': 'running',
                'ready': True
            }
        }
    }
    
    # When
    repo.save_pod_containers(namespace, pod_name, container_hashes, pod_info)
    
    # Then
    found_info = repo.find_by_hash(container_hash)
    assert found_info is not None
    assert found_info['pod_name'] == pod_name
    assert found_info['namespace'] == namespace

def test_container_removal_on_pod_update(repo):
    """파드 업데이트 시 컨테이너 제거 테스트"""
    # Given
    namespace = "test-ns"
    pod_name = "test-pod"
    old_container = "123456789012"  # 정확히 12자리
    new_container = "abcdef123456"  # 정확히 12자리
    
    # 초기 상태: old_container만 있는 파드
    initial_pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Running',
        'containers': {
            old_container: {
                'name': 'test-container',
                'state': 'running',
                'ready': True
            }
        }
    }
    repo.save_pod_containers(namespace, pod_name, {old_container}, initial_pod_info)
    
    # When: 새로운 컨테이너로 업데이트
    updated_pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Running',
        'containers': {
            new_container: {
                'name': 'test-container',
                'state': 'running',
                'ready': True
            }
        }
    }
    repo.save_pod_containers(namespace, pod_name, {new_container}, updated_pod_info)
    
    # Then
    assert repo.find_by_hash(old_container) is None  # 이전 컨테이너는 제거되어야 함
    assert repo.find_by_hash(new_container) is not None  # 새 컨테이너는 조회 가능해야 함

def test_pod_deletion(repo):
    """파드 삭제 테스트"""
    # Given
    namespace = "test-ns"
    pod_name = "test-pod"
    container_hash = "123456abcdef"  # 정확히 12자리
    
    pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Running',
        'containers': {
            container_hash: {
                'name': 'test-container',
                'state': 'running',
                'ready': True
            }
        }
    }
    repo.save_pod_containers(namespace, pod_name, {container_hash}, pod_info)
    
    # When
    repo.remove_pod_containers(pod_name, namespace)
    
    # Then
    assert repo.find_by_hash(container_hash) is None
    assert (namespace, pod_name) not in repo.pods

def test_multiple_containers_in_pod(repo):
    """하나의 파드에 여러 컨테이너가 있는 경우 테스트"""
    # Given
    namespace = "test-ns"
    pod_name = "test-pod"
    container1 = "111111111111"  # 정확히 12자리
    container2 = "222222222222"  # 정확히 12자리
    
    pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Running',
        'containers': {
            container1: {'name': 'c1', 'state': 'running', 'ready': True},
            container2: {'name': 'c2', 'state': 'running', 'ready': True}
        }
    }
    
    # When
    repo.save_pod_containers(namespace, pod_name, {container1, container2}, pod_info)
    
    # Then
    assert repo.find_by_hash(container1) is not None
    assert repo.find_by_hash(container2) is not None
    pod_key = (namespace, pod_name)
    assert len(repo.pods[pod_key]['container_hashes']) == 2

def test_invalid_pod_info(repo):
    """잘못된 파드 정보 저장 시도 테스트"""
    # Given
    invalid_pod_info = {'wrong_key': 'value'}  # required keys missing
    valid_hash = "123456789012"  # 정확히 12자리
    
    # When/Then
    with pytest.raises(ValueError):
        repo.save_pod_containers("ns", "pod", {valid_hash}, invalid_pod_info)

def test_hash_length_validation():
    """해시 길이 검증 테스트"""
    repo = ContainerHashRepository()
    namespace = "test-ns"
    pod_name = "test-pod"
    pod_info = {"namespace": namespace, "pod_name": pod_name}
    
    # 저장 시도시 검증
    with pytest.raises(ValueError):
        # 11자리 해시 (너무 짧음)
        repo.save_pod_containers(namespace, pod_name, {"12345678901"}, pod_info)
    
    with pytest.raises(ValueError):
        # 13자리 해시 (너무 김)
        repo.save_pod_containers(namespace, pod_name, {"1234567890123"}, pod_info)
    
    # 조회 시도시 검증
    with pytest.raises(ValueError):
        repo.find_by_hash("12345")  # 5자리 해시
        
    with pytest.raises(ValueError):
        repo.find_by_hash("1234567890123")  # 13자리 해시

def test_find_nonexistent_container(repo):
    """존재하지 않는 컨테이너 해시로 조회 테스트"""
    # When
    result = repo.find_by_hash("123456789012")  # 정확히 12자리
    
    # Then
    assert result is None

def test_find_after_pod_update(repo):
    """파드 정보 업데이트 후 조회 테스트"""
    # Given
    namespace = "test-ns"
    pod_name = "test-pod"
    container_hash = "abcdef123456"  # 정확히 12자리
    container_hashes = {container_hash}
    
    initial_pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Pending',
        'containers': {
            container_hash: {
                'name': 'test-container',
                'state': 'waiting',
                'ready': False
            }
        }
    }
    
    # When: 초기 저장
    repo.save_pod_containers(namespace, pod_name, container_hashes, initial_pod_info)
    
    # 파드 정보 업데이트
    updated_pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Running',
        'containers': {
            container_hash: {
                'name': 'test-container',
                'state': 'running',
                'ready': True
            }
        }
    }
    repo.save_pod_containers(namespace, pod_name, container_hashes, updated_pod_info)
    
    # Then
    found_info = repo.find_by_hash(container_hash)
    assert found_info is not None
    assert found_info['phase'] == 'Running'  # 업데이트된 정보가 조회되어야 함

def test_find_after_container_removal(repo):
    """컨테이너 제거 후 조회 테스트"""
    # Given
    namespace = "test-ns"
    pod_name = "test-pod"
    container1 = "aaaaaaaaaaaa"  # 정확히 12자리
    container2 = "bbbbbbbbbbbb"  # 정확히 12자리
    
    pod_info = {
        'namespace': namespace,
        'pod_name': pod_name,
        'phase': 'Running',
        'containers': {
            container1: {'name': 'c1', 'state': 'running', 'ready': True},
            container2: {'name': 'c2', 'state': 'running', 'ready': True}
        }
    }
    
    # When: 두 컨테이너로 시작
    repo.save_pod_containers(namespace, pod_name, {container1, container2}, pod_info)
    
    # container2만 남기고 업데이트
    pod_info['containers'].pop(container1)
    repo.save_pod_containers(namespace, pod_name, {container2}, pod_info)
    
    # Then
    assert repo.find_by_hash(container1) is None  # 제거된 컨테이너는 찾을 수 없어야 함
    assert repo.find_by_hash(container2) is not None  # 남은 컨테이너는 찾을 수 있어야 함

def test_save_and_find_with_hash_validation():
    """해시 길이에 따른 저장 및 조회 테스트"""
    repo = ContainerHashRepository()
    namespace = "default"
    pod_name = "test-pod"
    pod_info = {"namespace": namespace, "pod_name": pod_name}
    
    # 정상 케이스: 정확히 12자리 해시
    valid_hash = "123456789012"
    repo.save_pod_containers(namespace, pod_name, {valid_hash}, pod_info)
    
    # 동일한 해시로 조회 가능해야 함
    assert repo.find_by_hash(valid_hash) == pod_info
    
    # 12자리 미만 해시로 저장 시도시 실패해야 함
    with pytest.raises(ValueError):
        repo.save_pod_containers(namespace, pod_name, {"123"}, pod_info)
    
    # 12자리 미만 해시로 조회 시도시 실패해야 함
    with pytest.raises(ValueError):
        repo.find_by_hash("123")
        
    # 12자리 초과 해시로 저장 시도시 실패해야 함
    with pytest.raises(ValueError):
        repo.save_pod_containers(namespace, pod_name, {"1234567890123"}, pod_info)

def test_multiple_containers_with_same_prefix():
    """동일 prefix를 가진 다른 컨테이너 구분 테스트"""
    repo = ContainerHashRepository()
    
    # 서로 다른 12자리 해시
    hash1 = "123456789012"
    hash2 = "234567890123"
    
    # 첫 번째 컨테이너 저장
    pod1_info = {"namespace": "ns1", "pod_name": "pod1"}
    repo.save_pod_containers("ns1", "pod1", {hash1}, pod1_info)
    
    # 두 번째 컨테이너 저장
    pod2_info = {"namespace": "ns2", "pod_name": "pod2"}
    repo.save_pod_containers("ns2", "pod2", {hash2}, pod2_info)
    
    # 각각의 해시는 자신의 파드 정보를 반환해야 함
    assert repo.find_by_hash(hash1) == pod1_info
    assert repo.find_by_hash(hash2) == pod2_info

def test_remove_standardized_hashes():
    """해시의 삭제 테스트"""
    repo = ContainerHashRepository()
    namespace = "default"
    pod_name = "test-pod"
    pod_info = {"namespace": namespace, "pod_name": pod_name}
    
    # 12자리 해시로 저장
    hash_val = "123456789012"
    repo.save_pod_containers(namespace, pod_name, {hash_val}, pod_info)
    
    # 삭제 전 조회 가능 확인
    assert repo.find_by_hash(hash_val) == pod_info
    
    # 파드 삭제
    repo.remove_pod_containers(pod_name, namespace)
    
    # 삭제 후 조회 불가 확인
    assert repo.find_by_hash(hash_val) is None 