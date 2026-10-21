FROM python:3.7.10-slim
ENV PYTHON_VERSION=3.7.10

ENV SERVICE_NAME=ada_scanner
ENV SCANNER_CONF_PATH=/home/adadmin/conf/scanner.yaml

# for test env.
ENV TEST_TRAIT=c6dd002b714181fd7c273ee7fdda5d16

LABEL maintainer="dev@ada"
ARG ADA_VERSION=dev
LABEL version=${ADA_VERSION}
LABEL description="Docker image for ada system scanner service"

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's|deb.debian.org/debian|archive.debian.org/debian|g' /etc/apt/sources.list \
    && sed -i 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' /etc/apt/sources.list \
    && sed -i '/buster-updates/d' /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libffi-dev \
    liblzma-dev \
    tk-dev \
    uuid-dev \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python3.7 --version

RUN ln -s /usr/local/bin/python3.7 /usr/bin/python && \
    ln -s /usr/local/bin/pip3.7 /usr/bin/pip

RUN useradd -rm -d /home/adadmin -s /bin/bash -g root -G sudo -u 1001 adadmin

RUN set -x \
    && mkdir -p /home/adadmin/logs \
    && mkdir -p /home/adadmin/bin \
    && mkdir -p /home/adadmin/conf \
    && chmod 755 /home/adadmin \
    && chown -R adadmin:root /home/adadmin/logs \
    && chown -R adadmin:root /home/adadmin/conf \
    && mkdir -p /var/lib/scada \
    && mkdir -p /var/log/scada \
    && chown -R adadmin:root /var/log/scada \
    && chown -R adadmin:root /var/lib/scada

COPY scanner /home/adadmin/bin/scanner
COPY scanner.yaml /home/adadmin/conf/

USER adadmin
WORKDIR /home/adadmin

CMD ["bash", "-c", "./bin/scanner"]
