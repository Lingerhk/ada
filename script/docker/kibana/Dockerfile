# Using official Kibana image
FROM docker.elastic.co/kibana/kibana:8.18.8

ENV SERVICE_NAME=ada_kibana

LABEL maintainer="dev@ada"
ARG ADA_VERSION=dev
LABEL version=${ADA_VERSION}
LABEL description="Docker image for ada system kibana service"

# Copy custom configuration with proper ownership
USER root
COPY --chown=kibana:kibana config/kibana.yml /usr/share/kibana/config/kibana.yml
USER kibana
