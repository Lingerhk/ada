FROM scratch

LABEL maintainer="dev@ada"
ARG ADA_VERSION=dev
LABEL version=${ADA_VERSION}
LABEL description="Docker image for EasyTier tunnel service"

COPY script/docker-poc/ada-service/easytier-core /easytier-core

ENTRYPOINT ["/easytier-core"]
