import pytest
import aiohttp
import asyncio
from datetime import datetime
from unittest.mock import patch, MagicMock
from aiohttp import web
from src.api.client import APIClient
from src.process.types import ProcessType
from src.types.events import EnrichedProcessEvent

# 테스트용 이벤트 데이터
@pytest.fixture
def sample_event():
    return EnrichedProcessEvent(
        timestamp=datetime.now().isoformat(),
        pid=12345,
        process_type=ProcessType.USER_BINARY,
        binary_path="/home/coder/project/hw1/main",
        container_id="container123",
        cwd="/home/coder/project/hw1",
        args="./main arg1 arg2",
        error_flags="0b0",
        exit_code=0,
        pod_name="jcode-os-1-202012345-abc",
        namespace="jcode-os-1",
        class_div="os-1",
        student_id="202012345"
    )

@pytest.fixture
def api_client():
    with patch('src.api.client.settings') as mock_settings:
        mock_settings.api_endpoint = "http://test-api"
        mock_settings.api_timeout = 5.0
        return APIClient()

# 실제 HTTP 서버를 모킹하여 테스트
async def test_send_binary_execution_success(aiohttp_client, sample_event):
    # 테스트용 서버 설정
    async def handler(request):
        # 요청 검증
        assert request.match_info['class_div'] == 'os-1'
        assert request.match_info['hw_dir'] == 'hw1'
        assert request.match_info['student_id'] == '202012345'
        
        # 요청 바디 검증
        data = await request.json()
        assert data['pod_name'] == sample_event.pod_name
        assert data['container_id'] == sample_event.container_id
        assert data['pid'] == sample_event.pid
        assert data['binary_path'] == sample_event.binary_path
        assert data['working_dir'] == sample_event.cwd
        assert data['command_line'] == sample_event.args
        assert data['exit_code'] == sample_event.exit_code
        assert data['error_flags'] == sample_event.error_flags
        assert data['timestamp'] == sample_event.timestamp
        
        return web.json_response({"status": "success"})

    app = web.Application()
    app.router.add_post('/api/{class_div}/{hw_dir}/{student_id}/logs/run', handler)
    
    client = await aiohttp_client(app)
    
    # APIClient 설정
    with patch('src.api.client.settings') as mock_settings:
        mock_settings.api_endpoint = str(client.make_url(''))
        mock_settings.api_timeout = 5.0
        api_client = APIClient()
        
        # 테스트 실행
        result = await api_client.send_binary_execution(sample_event, "hw1")
        assert result is True

async def test_send_compilation_success(aiohttp_client, sample_event):
    # 테스트용 서버 설정
    async def handler(request):
        # 요청 검증
        assert request.match_info['class_div'] == 'os-1'
        assert request.match_info['hw_dir'] == 'hw1'
        assert request.match_info['student_id'] == '202012345'
        
        # 요청 바디 검증
        data = await request.json()
        assert data['pod_name'] == sample_event.pod_name
        assert data['container_id'] == sample_event.container_id
        assert data['pid'] == sample_event.pid
        assert data['compiler_path'] == sample_event.binary_path
        assert data['working_dir'] == sample_event.cwd
        assert data['command_line'] == sample_event.args
        assert data['exit_code'] == sample_event.exit_code
        assert data['error_flags'] == sample_event.error_flags
        assert data['timestamp'] == sample_event.timestamp
        assert data['source_file'] == '/home/coder/project/hw1/main.c'
        
        return web.json_response({"status": "success"})

    app = web.Application()
    app.router.add_post('/api/{class_div}/{hw_dir}/{student_id}/logs/build', handler)
    
    client = await aiohttp_client(app)
    
    # APIClient 설정
    with patch('src.api.client.settings') as mock_settings:
        mock_settings.api_endpoint = str(client.make_url(''))
        mock_settings.api_timeout = 5.0
        api_client = APIClient()
        
        # 테스트 실행
        result = await api_client.send_compilation(
            sample_event, 
            "hw1",
            "/home/coder/project/hw1/main.c"
        )
        assert result is True

async def test_api_error_handling(aiohttp_client, sample_event):
    # 테스트용 서버 설정
    async def handler(request):
        # 500 에러 응답
        return web.Response(status=500, text="Internal Server Error")

    app = web.Application()
    app.router.add_post('/api/{class_div}/{hw_dir}/{student_id}/logs/run', handler)
    
    client = await aiohttp_client(app)
    
    # APIClient 설정
    with patch('src.api.client.settings') as mock_settings:
        mock_settings.api_endpoint = str(client.make_url(''))
        mock_settings.api_timeout = 5.0
        api_client = APIClient()
        
        # 테스트 실행
        result = await api_client.send_binary_execution(sample_event, "hw1")
        assert result is False

async def test_network_error_handling(api_client, sample_event):
    # 잘못된 엔드포인트로 설정하여 네트워크 오류 시뮬레이션
    with patch('src.api.client.settings') as mock_settings:
        mock_settings.api_endpoint = "http://non-existent-endpoint"
        mock_settings.api_timeout = 1.0
        api_client = APIClient()
        
        # 테스트 실행
        result = await api_client.send_binary_execution(sample_event, "hw1")
        assert result is False

async def test_timeout_handling(aiohttp_client, sample_event):
    # 테스트용 서버 설정 - 의도적으로 지연 발생
    async def handler(request):
        await asyncio.sleep(2)  # 2초 지연
        return web.json_response({"status": "success"})

    app = web.Application()
    app.router.add_post('/api/{class_div}/{hw_dir}/{student_id}/logs/run', handler)
    
    client = await aiohttp_client(app)
    
    # APIClient 설정 - 1초 타임아웃
    with patch('src.api.client.settings') as mock_settings:
        mock_settings.api_endpoint = str(client.make_url(''))
        mock_settings.api_timeout = 1.0
        api_client = APIClient()
        
        # 테스트 실행
        result = await api_client.send_binary_execution(sample_event, "hw1")
        assert result is False 