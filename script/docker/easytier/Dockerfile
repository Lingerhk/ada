FROM scratch

LABEL maintainer="dev@ada"
LABEL version=2.9.1
LABEL description="Docker image for EasyTier tunnel service"

COPY script/docker-poc/ada-service/easytier-core /easytier-core

ENTRYPOINT ["/easytier-core"]
