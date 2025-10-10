FROM ubuntu:24.04

ENV SERVICE_NAME=ada_backend
ENV TASKER_CONF_PATH=/home/adadmin/conf/tasker.yaml
ENV APISERVER_CONF_PATH=/home/adadmin/conf/apiserver.yaml

LABEL maintainer="dev@ada"
LABEL version="2.9.1"
LABEL description="Docker image for ada system backend service"

RUN set -x \
    && apt-get update \
	&& apt-get install -y iputils-ping dnsutils traceroute netcat-openbsd nginx supervisor \
	&& rm -rf /var/lib/apt/lists/*

RUN useradd -rm -d /home/adadmin -s /bin/bash -g root -G sudo -u 1001 adadmin

RUN set -x \
    && mkdir -p /home/adadmin/logs \
    && mkdir -p /home/adadmin/bin \
    && mkdir -p /home/adadmin/conf \
    && mkdir -p /home/adadmin/download \
    && chmod 755 /home/adadmin \
    && chown -R adadmin:root /home/adadmin/logs \
    && chown -R adadmin:root /home/adadmin/download \
    && sed -i 's/worker_processes auto;/worker_processes 2;/' /etc/nginx/nginx.conf

RUN set -x \
    && mkdir -p /home/adadmin/download/report \
    && mkdir -p /home/adadmin/download/sensor \
    && chown -R adadmin:root /home/adadmin/download/report \
    && chown -R adadmin:root /home/adadmin/download/sensor

COPY adaegis.zip /home/adadmin/download/sensor/adaegis.zip
COPY install-adaegis.ps1 /home/adadmin/download/sensor/install-adaegis.ps1
COPY uninstall-adaegis.ps1 /home/adadmin/download/sensor/uninstall-adaegis.ps1

COPY conf/nginx.conf /etc/nginx/sites-available/default
COPY conf/supervisord.conf /etc/supervisor/supervisord.conf

COPY apiserver /home/adadmin/bin/
COPY task_server /home/adadmin/bin/
COPY task_worker /home/adadmin/bin/
COPY --chown=www-data static /home/adadmin/static

COPY apiserver.yaml /home/adadmin/conf/
COPY tasker.yaml /home/adadmin/conf/

USER root
WORKDIR /home/adadmin

EXPOSE 80/tcp 9092/udp

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]