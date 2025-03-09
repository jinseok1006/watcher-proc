#!/usr/bin/python3
import asyncio
import logging
from typing import Dict
from kubernetes_asyncio import client, config

from .utils.logging import setup_logging
from .process.types import ProcessType
from .process.filter import ProcessFilter
from .parser.compiler import CCompilerParser
from .parser.base import Parser
from .homework.checker import DefaultHomeworkChecker
from .bpf.collector import BPFCollector
from .core.processor import AsyncEventProcessor
from .container.repository import ContainerHashRepository
from .container.watcher import AsyncPodWatcher

def setup_parser_registry() -> Dict[ProcessType, Parser]:
    """파서 레지스트리 설정"""
    return {
        ProcessType.GCC: CCompilerParser(ProcessType.GCC),
        ProcessType.CLANG: CCompilerParser(ProcessType.CLANG)
    }

async def main():
    """메인 비동기 함수"""
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("[시작] 프로세스 및 컨테이너 감시자 시작")
    
    event_queue: asyncio.Queue = asyncio.Queue()
    collector = None  # collector 변수를 미리 선언
    
    try:
        # 1. 쿠버네티스 컴포넌트 초기화
        try:
            config.load_incluster_config()
            logger.info("[쿠버네티스] 인클러스터 설정 로드 완료")
        except config.ConfigException:
            logger.warning("[쿠버네티스] 인클러스터 설정 로드 실패, kubeconfig 사용 시도")
            # sudo 실행시에도 올바른 kubeconfig 사용
            await config.load_kube_config(
                config_file="/home/ubuntu/.kube/config"  # 실제 경로로 수정 필요
            )
        
        k8s_api = client.CoreV1Api()
        container_repository = ContainerHashRepository()
        
        watchers = [
            AsyncPodWatcher("jcode-os-1", container_repository, k8s_api),
            AsyncPodWatcher("watcher", container_repository, k8s_api)
        ]
        
        # 2. 기존 컴포넌트 초기화
        parser_registry = setup_parser_registry()
        homework_checker = DefaultHomeworkChecker()
        
        collector = BPFCollector(event_queue)
        collector.load_program()
        collector.start_polling()
        
        processor = AsyncEventProcessor(
            event_queue=event_queue,
            parser_registry=parser_registry,
            homework_checker=homework_checker,
            container_repository=container_repository
        )
        
        # 3. 워쳐 태스크들을 백그라운드로 시작
        watcher_tasks = [asyncio.create_task(w.start()) for w in watchers]
        
        try:
            # 메인 프로세스 실행하면서 워쳐 태스크들도 함께 실행
            await asyncio.gather(processor.run(), *watcher_tasks)
            # await processor.run()
            
        except asyncio.CancelledError:
            logger.info("[종료] 프로그램 종료 요청")
            raise
            
        except Exception as e:
            logger.error(f"[오류] 실행 중 오류 발생: {e}")
            raise
            
        finally:
            # 워쳐 태스크들 정리
            for task in watcher_tasks:
                if not task.done():
                    task.cancel()
            
            await asyncio.gather(*watcher_tasks, return_exceptions=True)
            
    finally:
        if collector:  # collector가 초기화된 경우에만 stop_polling 호출
            collector.stop_polling()
        await event_queue.join()
        logger.info("[종료] 정리 작업 완료")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("[종료] 프로그램을 종료합니다...") 