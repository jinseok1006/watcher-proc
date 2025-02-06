import time
from datetime import datetime

class TimeManager:
    def __init__(self):
        # 시간 오프셋 초기화
        self.start_monotonic_ns = time.monotonic_ns()
        self.start_epoch = time.time()
        self.time_offset = self.start_epoch - (self.start_monotonic_ns / 1e9)
        self.local_tz = datetime.now().astimezone().tzinfo

    def get_formatted_time(self, event_timestamp_ns):
        """이벤트 타임스탬프를 포맷팅된 시간 문자열로 변환"""
        timestamp_monotonic = event_timestamp_ns / 1e9
        timestamp_epoch = timestamp_monotonic + self.time_offset
        dt = datetime.fromtimestamp(timestamp_epoch, tz=self.local_tz)
        return dt.strftime("%Y-%m-%d %H:%M:%S") 