"""프로세스 모니터링 메인 프로그램

BPF 프로그램을 실행하고 이벤트를 처리하는 메인 로직을 구현합니다.
"""

import asyncio
import logging
from pathlib import Path

from src.bpf.collector import BPFCollector
from src.bpf.event import RawBpfEvent
from src.events.models import EventBuilder
from src.process.filter import ProcessFilter
from src.homework.checker import DefaultHomeworkChecker
from src.handlers.chain import build_handler_chain

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def handle_event(event: RawBpfEvent, handler_chain):
    """이벤트 처리
    
    Args:
        event: BPF 프로그램으로부터 수신한 이벤트
        handler_chain: 이벤트 처리 핸들러 체인
    """
    try:
        logger.info(f"[이벤트 수신] PID: {event.pid}, 실행 파일: {event.binary_path}")
        
        # 이벤트 빌더 생성
        builder = EventBuilder(event)
        logger.debug("[이벤트 빌더] 생성 완료")
        
        # 핸들러 체인 실행
        result = await handler_chain.handle(builder)
        if result:
            logger.info(f"[이벤트 처리 완료] PID: {event.pid}, 프로세스 타입: {result.process.type if result.process else 'Unknown'}")
        else:
            logger.warning(f"[이벤트 처리 중단] PID: {event.pid}")
        
    except Exception as e:
        logger.error(f"[이벤트 처리 실패] PID: {event.pid}, 오류: {str(e)}")

async def process_events(event_queue: asyncio.Queue, handler_chain):
    """이벤트 큐로부터 이벤트를 가져와 처리
    
    Args:
        event_queue: BPF 이벤트 큐
        handler_chain: 이벤트 처리 핸들러 체인
    """
    logger.info("[이벤트 처리] 이벤트 처리 루프 시작")
    event_count = 0
    
    while True:
        try:
            event = await event_queue.get()
            event_count += 1
            logger.info(f"[이벤트 처리] 큐에서 이벤트 수신 (총 처리 이벤트: {event_count}개)")
            
            try:
                await handle_event(event, handler_chain)
            except Exception as e:
                logger.error(f"[이벤트 처리] 이벤트 처리 중 오류 발생: {str(e)}")
            finally:
                event_queue.task_done()
                
        except Exception as e:
            logger.error(f"[이벤트 처리] 이벤트 수신 중 오류 발생: {str(e)}")

async def main():
    """메인 함수"""
    collector = None
    event_queue = asyncio.Queue()
    
    try:
        logger.info("[시작] 프로세스 모니터링 시작")
        
        # BPF 컬렉터 초기화 및 시작
        logger.info("[초기화] BPF 컬렉터 초기화 시작")
        collector = BPFCollector(event_queue)
        collector.load_program()
        collector.start_polling()
        logger.info("[초기화] BPF 컬렉터 초기화 완료")
        
        # 핸들러 체인 구성
        logger.info("[초기화] 핸들러 체인 구성 시작")
        homework_checker = DefaultHomeworkChecker()
        process_filter = ProcessFilter(homework_checker)
        handler_chain = build_handler_chain(
            process_filter=process_filter,
            homework_checker=homework_checker
        )
        logger.info("[초기화] 핸들러 체인 구성 완료")
        
        # 이벤트 처리 시작
        logger.info("[실행] 이벤트 처리 시작")
        await process_events(event_queue, handler_chain)
            
    except KeyboardInterrupt:
        logger.info("[종료] 키보드 인터럽트로 프로그램 종료")
    except Exception as e:
        logger.error(f"[오류] 프로그램 실행 중 오류 발생: {str(e)}")
        raise
    finally:
        if collector:
            logger.info("[종료] BPF 컬렉터 정리 시작")
            collector.stop_polling()
            await event_queue.join()
            logger.info("[종료] BPF 컬렉터 정리 완료")
        logger.info("[종료] 프로그램 종료")

if __name__ == "__main__":
    asyncio.run(main()) 