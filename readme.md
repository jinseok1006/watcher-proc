# 컨테이너 모니터링을 위한 Docker 실행 옵션 가이드

## 요구사항
다른 컨테이너를 감시하는 bpf프로세스 또한 컨테이너로 배포되어야 함.

## 기본 실행 명령어
```bash
docker run -it \
--privileged \
--pid=host \
--net=host \
--uts=host \
--ipc=host \
-v /:/host:ro \
-v /sys/kernel/debug:/sys/kernel/debug \
-v /lib/modules:/lib/modules \
-v /usr/src:/usr/src \
-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
-v /proc:/proc \
bpf:test
```

## 권한 설정

### Privileged 모드
- `--privileged`
  - 컨테이너에 호스트와 동등한 수준의 권한 부여
  - 호스트의 모든 디바이스(/dev/) 접근 권한 획득
  - SELinux/AppArmor 등 보안 정책 우회 가능
  - 호스트 커널의 모든 기능(capabilities) 사용 가능
  - 새로운 디바이스 생성 및 수정 권한
  - 시스템 수준의 작업(시스템 시간 변경, 커널 모듈 로드 등) 수행 가능
  - 사용 이유: eBPF 프로그램은 커널 수준의 접근 권한이 필요하므로 필수

## 네임스페이스 설정

### PID 네임스페이스
- `--pid=host`
  - 호스트 PID 네임스페이스를 컨테이너와 공유
  - 호스트에서 실행 중인 모든 프로세스가 컨테이너 내부에서 보임
  - 프로세스 ID가 호스트와 동일하게 매핑
  - 호스트의 프로세스 트리 전체 접근 가능
  - init 프로세스(PID 1)를 포함한 모든 시스템 프로세스 확인
  - 프로세스 상태, 리소스 사용량 등 모니터링 가능

### Network 네임스페이스
- `--net=host`
  - 컨테이너가 호스트의 네트워크 스택을 직접 사용
  - 호스트의 모든 네트워크 인터페이스 사용 가능
  - 별도의 가상 네트워크 인터페이스 생성하지 않음
  - 호스트의 라우팅 테이블, iptables 규칙 등 공유
  - 네트워크 성능 오버헤드가 없음 (컨테이너 네트워크 브릿지를 거치지 않음)
  - 호스트의 모든 포트에 직접 접근 가능

### UTS 네임스페이스
- `--uts=host`
  - UNIX Time-sharing System 네임스페이스 공유
  - 호스트의 호스트명과 NIS 도메인 이름을 컨테이너와 공유
  - 시스템 식별자(hostname, domainname) 변경 가능
  - 클러스터 환경에서 노드 식별에 중요
  - 시스템 모니터링 도구에서 정확한 호스트 정보 확인 가능

### IPC 네임스페이스
- `--ipc=host`
  - Inter-Process Communication 리소스 공유
  - 호스트의 모든 IPC 객체에 접근 가능:
    - 공유 메모리 세그먼트(SHM)
    - 세마포어
    - 메시지 큐
  - 호스트와 컨테이너 간 메모리 공유 가능
  - 시스템 전체의 프로세스 간 통신 모니터링 가능

## 볼륨 마운트

### 호스트 파일시스템
- `-v /:/host:ro`
  - 호스트의 전체 파일시스템을 컨테이너에 읽기 전용으로 마운트
  - 호스트의 모든 파일과 디렉토리 구조 접근 가능
  - 시스템 구성 파일, 로그 파일 등 분석 가능
  - 읽기 전용(ro) 옵션으로 호스트 파일시스템 보호
  - 파일 시스템 감사 및 모니터링에 활용

### 커널 디버깅
- `-v /sys/kernel/debug:/sys/kernel/debug`
  - 커널의 디버그 파일시스템(debugfs) 접근
  - BPF 프로그램 로드 및 관리에 필수
  - 커널 추적 이벤트 접근
  - 성능 분석 데이터 수집
  - 커널 서브시스템 상태 모니터링
  - ftrace, kprobes 등 커널 트레이싱 도구 사용

### 시스템 모듈
- `-v /lib/modules:/lib/modules`
  - 호스트 커널 모듈 디렉토리 접근
  - 로드된 커널 모듈 정보 확인
  - 모듈 의존성 정보 접근
  - 커널 모듈 심볼 테이블 참조

- `-v /usr/src:/usr/src`
  - 커널 소스 코드 및 헤더 파일 접근
  - BPF 프로그램 컴파일에 필요한 커널 헤더 참조
  - 커널 데이터 구조 정의 접근
  - 커스텀 BPF 프로그램 개발 지원

### 프로세스 정보
- `-v /proc:/proc`
  - procfs 파일시스템 접근
  - 실시간 프로세스 정보 수집
  - 시스템 상태 및 통계 정보 접근
  - 프로세스별 메모리, CPU 사용량 등 모니터링
  - 커널 파라미터 확인 및 설정

- `-v /sys/fs/cgroup:/sys/fs/cgroup:ro`
  - cgroup 파일시스템 읽기 전용 접근
  - 컨테이너 리소스 제한 및 사용량 모니터링
  - CPU, 메모리, 디스크 I/O 제어 정보
  - 컨테이너 격리 상태 확인
  - 리소스 사용량 통계 수집

## 보안 고려사항
1. 권한 최소화
   - 필요한 권한만 부여
   - 가능한 경우 Privileged 모드 대신 특정 Capabilities 사용

2. 접근 제어
   - 볼륨 마운트시 읽기 전용 설정
   - 중요 시스템 파일 보호

3. 모니터링
   - 컨테이너 활동 로깅
   - 비정상 행위 탐지

4. 네트워크 보안
   - 필요한 포트만 노출
   - 네트워크 정책 적용 

## 대체 실행 방법 (최소 권한)
```bash
docker run -it \
--cap-drop=ALL \
--cap-add=SYS_ADMIN \
--cap-add=SYS_PTRACE \
--pid=host \
--net=host \
--uts=host \
--ipc=host \
-v /:/host:ro \
-v /sys/kernel/debug:/sys/kernel/debug \
-v /lib/modules:/lib/modules \
-v /usr/src:/usr/src \
-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
-v /proc:/proc \
bpf:test
```

### Capabilities
- `--cap-add=SYS_ADMIN`
  - BPF 시스템콜 사용 권한
  - 커널 기능 접근에 필수
  - 특수 파일시스템(debugfs 등) 마운트
  - 커널 모듈 관리

- `--cap-add=SYS_PTRACE`
  - 프로세스 추적 권한
  - 다른 프로세스의 메모리와 상태 접근
  - 프로세스 모니터링에 필요