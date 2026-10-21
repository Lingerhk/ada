FROM mongo:7.0.14


ENV SERVICE_NAME=ada_mongodb

LABEL maintainer="dev@ada"
ARG ADA_VERSION=dev
LABEL version=${ADA_VERSION}
LABEL description="Docker image for ada system mongodb service"

COPY 01-init_user.js /docker-entrypoint-initdb.d/01-init_user.js
COPY 02-init_db.js /docker-entrypoint-initdb.d/02-init_db.js