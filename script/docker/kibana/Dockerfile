# https://github.com/bitnami/bitnami-docker-kibana  
FROM bitnami/kibana:8.17.4

ENV SERVICE_NAME=ada_kibana

LABEL maintainer="dev@ada"
LABEL version="2.9.1"
LABEL description="Docker image for ada system kibana service"

COPY config/kibana.yml /opt/bitnami/kibana/config/kibana.yml
