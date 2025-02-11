#!/usr/bin/env python3
"""
컨테이너 프로세스 추적 프로그램
- sched_process_exec 및 sched_process_exit 트레이스포인트에 연결
- 컨테이너 cgroup 정보 파싱
- GCC 실행 결과(성공/실패) 추적
"""
from bcc import BPF
from time_utils import TimeManager
from container_utils import get_container_id, HashPIDMap, get_process_path, get_process_cmdline

# BPF 프로그램 로드
with open('src/bpf_program.c', 'r') as f:
    bpf_program = f.read()

class ProcessTracer:
    def __init__(self):
        self.bpf = BPF(text=bpf_program)
        self.time_manager = TimeManager()
        self.hash_pid_map = HashPIDMap()
        
        # 트레이스포인트 연결
        self.bpf.attach_tracepoint(tp="sched:sched_process_exit", fn_name="sched_proc_exit_handler")
        self.bpf.attach_tracepoint(tp="sched:sched_process_exec", fn_name="sched_proc_exec_handler")

    def handle_event(self, cpu, data, size):
        """이벤트 처리 함수"""
        event = self.bpf["events"].event(data)
        pid = event.pid
        comm = event.comm.decode("utf-8", "replace")
        formatted_time = self.time_manager.get_formatted_time(event.timestamp)

        if event.event_type == 0:  # EXEC 이벤트
            container_hash = get_container_id(pid)
            if container_hash:
                self.hash_pid_map.add(pid, container_hash)
                exe_path = get_process_path(pid)
                cmdline = get_process_cmdline(pid)
                msg = f"[{formatted_time}] EXEC Container={container_hash} PID={pid} Process={comm} Path={exe_path} CMD={cmdline}\n"
                print(msg, end="")
            return

        # EXIT 이벤트 처리
        try:
            proc_info = self.hash_pid_map.get(pid)
        except KeyError:
            print(f"[{formatted_time}] EXIT PID={pid} Process={comm} (감시 대상 아님) (Exit Code: {event.exit_code})\n")
            return

        exit_code = event.exit_code
        status = "Success" if exit_code == 0 else f"Failure"
        msg = f"[{formatted_time}] EXIT Container={proc_info.container_hash} PID={pid} Process={comm} Status={status} (Exit Code: {exit_code}) Path={proc_info.exe_path} CMD={proc_info.cmdline}\n"
        print(msg, end="")

    def run(self):
        """메인 실행 루프"""
        self.bpf["events"].open_perf_buffer(self.handle_event)
        print("컨테이너 프로세스 추적을 시작합니다. 종료하려면 Ctrl+C를 누르세요.")
        try:
            while True:
                self.bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            print("\n추적이 중지되었습니다.")


if __name__ == "__main__":
    tracer = ProcessTracer()
    tracer.run()
