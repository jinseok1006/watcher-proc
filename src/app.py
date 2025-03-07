#!/usr/bin/python3
import asyncio
import logging
from typing import Dict

from .utils.logging import setup_logging
from .process.types import ProcessType
from .process.filter import ProcessFilter
from .parser.compiler import CCompilerParser
from .parser.base import Parser
from .homework.checker import DefaultHomeworkChecker
from .bpf.collector import BPFCollector
from .core.processor import AsyncEventProcessor

def setup_parser_registry() -> Dict[ProcessType, Parser]:
    """파서 레지스트리 설정"""
    return {
        ProcessType.GCC: CCompilerParser(ProcessType.GCC),
        ProcessType.CLANG: CCompilerParser(ProcessType.CLANG)
    }

async def main():
    """메인 비동기 함수"""
    # 로깅 설정
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("[시작] 프로세스 감시자 시작")
    
    # 이벤트 큐 생성
    event_queue: asyncio.Queue = asyncio.Queue()
    
    try:
        # 컴포넌트 초기화
        parser_registry = setup_parser_registry()
        homework_checker = DefaultHomeworkChecker()
        
        # BPF 컬렉터 초기화 및 시작
        collector = BPFCollector(event_queue)
        collector.load_program()
        collector.start_polling()
        
        # 이벤트 프로세서 초기화 및 실행
        processor = AsyncEventProcessor(
            event_queue=event_queue,
            parser_registry=parser_registry,
            homework_checker=homework_checker
        )
        
        # 이벤트 처리 시작
        await processor.run()
        
    except asyncio.CancelledError:
        logger.info("[종료] 종료 신호 수신")
        collector.stop_polling()
    except Exception as e:
        logger.error(f"[오류] 프로세스 감시자 실행 중 오류 발생: {e}")
        raise
    finally:
        # 남은 이벤트 처리 대기
        await event_queue.join()
        logger.info("[종료] 정리 작업 완료")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("[종료] 프로그램을 종료합니다...") 