# Using official Elasticsearch image
FROM docker.elastic.co/elasticsearch/elasticsearch:8.18.8

ENV SERVICE_NAME=ada_elasticsearch

LABEL maintainer="dev@ada"
ARG ADA_VERSION=dev
LABEL version=${ADA_VERSION}
LABEL description="Docker image for ada system elasticsearch service"

# Copy custom configuration as root, then switch to elasticsearch user
USER root
COPY --chown=elasticsearch:elasticsearch config/elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml
USER elasticsearch
