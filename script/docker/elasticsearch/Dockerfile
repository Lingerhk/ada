# https://github.com/bitnami/bitnami-docker-elasticsearch
FROM bitnami/elasticsearch:8.17.4

ENV SERVICE_NAME=ada_elasticsearch

LABEL maintainer="dev@ada"
LABEL version="2.9.1"
LABEL description="Docker image for ada system elasticsearch service"

COPY config/elasticsearch.yml /opt/bitnami/elasticsearch/config/elasticsearch.yml
