FROM curlimages/curl:latest

ENV SERVICE_NAME=ada_elasticsearch_setup

LABEL maintainer="dev@ada"
LABEL version="2.9.1"
LABEL description="Elasticsearch setup service for ADAegis - configures passwords and optionally creates Kibana data views"

# Copy the setup script
COPY --chown=curl_user:curl_user setup.sh /setup.sh

# Make script executable
USER root
RUN chmod +x /setup.sh
USER curl_user

# Set the entrypoint
ENTRYPOINT ["/bin/sh", "/setup.sh"]
