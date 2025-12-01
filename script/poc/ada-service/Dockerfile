FROM ubuntu:24.04

ENV SERVICE_NAME=ada_service
ENV TASKER_CONF_PATH=/home/adadmin/conf/tasker.yaml
ENV APISERVER_CONF_PATH=/home/adadmin/conf/apiserver.yaml
ENV ENGINE_CONF_PATH=/home/adadmin/conf/engine.yaml

# Temporary solution for test/uat/poc
ENV TEST_TRAIT=8e9bc696dd9f5c2c522ed50dadd206b3

LABEL maintainer="dev@ada"
LABEL version=2.9.1
LABEL description="Docker image for ada system all-in-one service (backend + engine)"

# Install dependencies for backend
ENV DEBIAN_FRONTEND=noninteractive
RUN set -x \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        iputils-ping curl wget net-tools \
        dnsutils \
        traceroute \
        netcat-openbsd \
        nginx \
        supervisor \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Update CA certificates
RUN update-ca-certificates

# Create user
RUN useradd -rm -d /home/adadmin -s /bin/bash -g root -G sudo -u 1001 adadmin

# Create directories
RUN set -x \
    && mkdir -p /home/adadmin/logs \
    && mkdir -p /home/adadmin/bin \
    && mkdir -p /home/adadmin/conf \
    && mkdir -p /home/adadmin/download \
    && mkdir -p /home/adadmin/download/report \
    && mkdir -p /home/adadmin/download/sensor \
    && mkdir -p /home/adadmin/rules/flow \
    && mkdir -p /home/adadmin/rules/winlog \
    && mkdir -p /home/adadmin/rules/pktlog \
    && chmod 755 /home/adadmin \
    && chown -R adadmin:root /home/adadmin/logs \
    && chown -R adadmin:root /home/adadmin/download \
    && chown -R adadmin:root /home/adadmin/rules \
    && chown -R adadmin:root /home/adadmin/conf \
    && sed -i 's/worker_processes auto;/worker_processes 2;/' /etc/nginx/nginx.conf

# Copy sensor files
COPY adaegis.zip /home/adadmin/download/sensor/adaegis.zip
COPY install-adaegis.ps1 /home/adadmin/download/sensor/install-adaegis.ps1
COPY uninstall-adaegis.ps1 /home/adadmin/download/sensor/uninstall-adaegis.ps1

# Copy nginx and supervisor config
COPY conf/nginx.conf /etc/nginx/sites-available/default
COPY conf/supervisord.conf /etc/supervisor/supervisord.conf

# Copy backend binaries
COPY apiserver /home/adadmin/bin/
COPY task_server /home/adadmin/bin/
COPY task_worker /home/adadmin/bin/

# Copy engine binary
COPY engine /home/adadmin/bin/

# Copy frps binary and config
COPY frps /home/adadmin/bin/
COPY frps.ini /home/adadmin/conf/

# Copy frpc binary and config
COPY frpc /home/adadmin/bin/
COPY frpc.ini /home/adadmin/conf/

# Copy static files
COPY --chown=www-data static /home/adadmin/static

# Copy config files
COPY apiserver.yaml /home/adadmin/conf/
COPY tasker.yaml /home/adadmin/conf/
COPY engine.yaml /home/adadmin/conf/

USER root
WORKDIR /home/adadmin

EXPOSE 80/tcp 9092/udp 8090/tcp

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
