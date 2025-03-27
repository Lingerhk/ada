FROM mongo:7.0.14


ENV SERVICE_NAME=ada_mongodb

LABEL maintainer="dev@ada"
LABEL version="2.9.1"
LABEL description="Docker image for ada system mongodb service"

COPY 01-init_user.js /docker-entrypoint-initdb.d/01-init_user.js
COPY 02-init_db.js /docker-entrypoint-initdb.d/02-init_db.js 
