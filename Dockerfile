# Ubuntu 베이스 이미지 사용
FROM ubuntu:24.04

# 커널 버전 설정
ARG KERNEL_VERSION=6.8.0-39-generic

# Python 및 필수 패키지 설치
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    bpfcc-tools \
    linux-headers-${KERNEL_VERSION} \
    kmod \
    python3-bpfcc \
    && rm -rf /var/lib/apt/lists/*

# 심볼릭 링크 생성
RUN ln -s /usr/src/linux-headers-${KERNEL_VERSION} /lib/modules/${KERNEL_VERSION}/build

WORKDIR /app

COPY src ./src

ENTRYPOINT ["python3"]
CMD ["src/main.py"]
