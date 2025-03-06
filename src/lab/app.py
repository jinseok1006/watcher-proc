#!/usr/bin/env python3
from bcc import BPF
import json
import sys
import os

class ContainerExitTracer:
    def __init__(self):
        # BPF 프로그램 로드
        bpf_source = self._load_bpf_program()
        self.bpf = BPF(text=bpf_source)
        self.bpf.attach_tracepoint(tp="sched:sched_process_exit", fn_name="trace_exit")

    def _load_bpf_program(self):
        # BPF 프로그램 파일 읽기
        current_dir = os.path.dirname(os.path.abspath(__file__))
        bpf_file = os.path.join(current_dir, "bpf_exit.c")
        
        with open(bpf_file, 'r') as f:
            return f.read()

    def _print_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        output = {
            "pid": event.pid,
            "command": event.comm.decode('utf-8').rstrip('\x00'),
            "container_id": event.container_id.decode('utf-8').rstrip('\x00'),
            "exit_code": event.exit_code
        }
        print(json.dumps(output))

    def run(self):
        self.bpf["events"].open_perf_buffer(self._print_event)
        print("gcc, gdb, g++ 프로세스 종료 추적 중...", file=sys.stderr)
        print("Ctrl+C로 종료하세요.", file=sys.stderr)
        
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("추적을 종료합니다.", file=sys.stderr)

def main():
    tracer = ContainerExitTracer()
    tracer.run()

if __name__ == "__main__":
    main()
