FROM ubuntu:24.04
ENV PYTHON_VERSION=3.7.10

ENV SERVICE_NAME=ada_scanner
ENV SCANNER_CONF_PATH=/home/adadmin/conf/scanner.yaml

LABEL maintainer="dev@ada"
LABEL version="2.6"
LABEL description="Docker image for ada system scanner service"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libncurses-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libffi-dev \
    liblzma-dev \
    tk-dev \
    uuid-dev \
    xz-utils \
    ca-certificates \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN wget https://www.python.org/ftp/python/3.7.10/Python-3.7.10.tgz && \
    tar xzf Python-3.7.10.tgz && \
    rm Python-3.7.10.tgz

# 编译并安装 Python 3.7
WORKDIR /usr/src/Python-3.7.10
RUN ./configure --enable-optimizations --disable-profiling && \
    make -j"$(nproc)" && \
    make install



# 验证 Python 安装版本
RUN python3.7 --version

# 设置默认 Python 版本（可选）
RUN ln -s /usr/local/bin/python3.7 /usr/bin/python && \
    ln -s /usr/local/bin/pip3.7 /usr/bin/pip

RUN useradd -rm -d /home/adadmin -s /bin/bash -g root -G sudo -u 1001 adadmin

RUN set -x \
    && mkdir -p /home/adadmin/logs \
    && mkdir -p /home/adadmin/bin \
    && mkdir -p /home/adadmin/conf \
    && mkdir -p /var/lib/scada \
    && mkdir -p /var/log/scada \
    && chown -R adadmin:root /var/log/scada \
    && chown -R adadmin:root /var/lib/scada

COPY scanner /home/adadmin/bin/
COPY scanner.yaml /home/adadmin/conf/

USER adadmin
WORKDIR /home/adadmin

#CMD ["./bin/scanner"]
CMD ["bash", "-c", "./bin/scanner"]