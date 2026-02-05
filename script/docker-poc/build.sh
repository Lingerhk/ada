#!/bin/bash

set -euo pipefail

version=2.9.1
root_path="/home/adadmin/adaegis"
ada_path="${root_path}/ada"
web_path="${root_path}/ada-web"
poc_path="${ada_path}/script/docker-poc"
docker_path="${ada_path}/script/docker"
portal_service_path="${poc_path}/ada-service"
poc_server="${POC_SERVER:-adadmin@192.168.7.8}"
poc_remote_path="${POC_REMOTE_PATH:-/home/adadmin/ada-poc}"

registry_url="${PORTAL_REGISTRY:-docker.adaegis.net}"
portal_image="${PORTAL_IMAGE:-${registry_url}/ada_portal:${version}}"

export GOCACHE="${GOCACHE:-/tmp/go-build-cache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/go-mod-cache}"
export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/docker-config}"
mkdir -p "${GOCACHE}" "${GOMODCACHE}" "${DOCKER_CONFIG}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

assert_paths() {
    if [ ! -d "${poc_path}" ]; then
        log_error "docker-poc path not found: ${poc_path}"
        exit 1
    fi

    if [ ! -d "${docker_path}" ]; then
        log_error "docker path not found: ${docker_path}"
        exit 1
    fi
}

build_frontend() {
    log_info "Building frontend..."
    cd "${web_path}" || exit
    npm run build
    rm -rf "${portal_service_path}/static"
    cp -r "${web_path}/dist" "${portal_service_path}/static"
    log_info "Frontend build completed"
}

prepare_portal_files() {
    log_info "Preparing portal files..."
    cd "${ada_path}" || exit
    make apiserver

    cp "${ada_path}/bin/apiserver" "${portal_service_path}/"
    cp "${ada_path}/agent/script/adaegis.zip" "${portal_service_path}/"
    cp "${ada_path}/agent/script/install-adaegis.ps1" "${portal_service_path}/"
    cp "${ada_path}/agent/script/uninstall-adaegis.ps1" "${portal_service_path}/"
}

build_portal() {
    build_frontend
    prepare_portal_files

    log_info "Building portal image: ${portal_image}"
    docker build --network=host -f "${portal_service_path}/Dockerfile.portal" -t "${portal_image}" "${portal_service_path}"
    log_info "Portal image built successfully"
}

build_local_component() {
    local component="$1"
    (cd "${docker_path}" && ./build.sh build "${component}")
}

build_local_all() {
    build_local_component backend
    build_local_component engine
    build_local_component scanner
    build_local_component zeek
    build_local_component kibana
    build_local_component elasticsearch
    build_local_component elasticsearch-setup
}

package_local_component() {
    local component="$1"
    (cd "${docker_path}" && ./build.sh package "${component}")
}

push_portal() {
    log_info "Pushing portal image: ${portal_image}"
    docker push "${portal_image}"
}

sync_poc_configs() {
    log_info "Syncing POC compose + configs to ${poc_server}..."
    ssh "${poc_server}" "mkdir -p ${poc_remote_path}/ada-service"
    ssh "${poc_server}" "if [ -f ${poc_remote_path}/docker-compose.yml ]; then cp ${poc_remote_path}/docker-compose.yml ${poc_remote_path}/docker-compose.yml.bak.$(date +%Y%m%d%H%M%S); fi"
    scp "${poc_path}/docker-compose.yml" "${poc_server}:${poc_remote_path}/"
    scp "${poc_path}/ada-service/scanner.yaml" "${poc_server}:${poc_remote_path}/ada-service/"
    scp "${poc_path}/ada-service/apiserver.backend.yaml" "${poc_server}:${poc_remote_path}/ada-service/"
    scp "${poc_path}/ada-service/tasker.yaml" "${poc_server}:${poc_remote_path}/ada-service/"
    scp "${poc_path}/ada-service/engine.yaml" "${poc_server}:${poc_remote_path}/ada-service/"
}

deploy_service() {
    local component="$1"
    local do_sync="${2:-true}"
    local image=""
    local service=""
    local tar=""

    case "${component}" in
        backend)
            image="ada_backend"
            service="ada_backend"
            tar="ada_backend_${version}.tar"
            ;;
        engine)
            image="ada_engine"
            service="ada_engine"
            tar="ada_engine_${version}.tar"
            ;;
        scanner)
            image="ada_scanner"
            service="ada_scanner"
            tar="ada_scanner_${version}.tar"
            ;;
        zeek)
            image="ada_zeek"
            service="ada_zeek"
            tar="ada_zeek_${version}.tar"
            ;;
        kibana)
            image="ada_kibana"
            service="ada_kibana"
            tar="ada_kibana_${version}.tar"
            ;;
        elasticsearch)
            image="ada_elasticsearch"
            service="ada_elasticsearch"
            tar="ada_elasticsearch_${version}.tar"
            ;;
        elasticsearch-setup)
            image="ada_elasticsearch_setup"
            service="ada_elasticsearch_setup"
            tar="ada_elasticsearch_setup_${version}.tar"
            ;;
        *)
            log_error "Unknown component: ${component}"
            exit 1
            ;;
    esac

    if [ ! -f "${docker_path}/${tar}" ]; then
        log_error "Missing package: ${docker_path}/${tar} (run: ./build.sh package ${component})"
        exit 1
    fi

    if [ "${do_sync}" = "true" ]; then
        sync_poc_configs
    fi

    log_info "Deploying ${image}:${version} to ${poc_server}..."
    scp "${docker_path}/${tar}" "${poc_server}:/tmp/"
    ssh "${poc_server}" "cd ${poc_remote_path} && docker compose down ${service} || true"
    ssh "${poc_server}" "docker rmi -f ${image}:${version} 2>/dev/null || true"
    ssh "${poc_server}" "docker load -i /tmp/${tar}"
    ssh "${poc_server}" "cd ${poc_remote_path} && docker compose up -d ${service}"
    ssh "${poc_server}" "cd ${poc_remote_path} && docker compose ps ${service}"
    ssh "${poc_server}" "rm -f /tmp/${tar}"
}

deploy_all() {
    local skip_es="${1:-true}"
    sync_poc_configs
    if [ "${skip_es}" != "true" ]; then
        deploy_service elasticsearch false
        deploy_service elasticsearch-setup false
        deploy_service kibana false
    else
        log_warn "Skipping elasticsearch/elasticsearch-setup/kibana deploy (ES already running)."
    fi
    deploy_service backend false
    deploy_service engine false
    deploy_service zeek false
    deploy_service scanner false
}

usage() {
    cat <<EOF
Usage: $0 <command> [component]

Commands:
  build [component]    Build images
  package [component]  Package local images
  deploy [component]   Deploy packaged images to POC server
  release [component]  Build, package, and deploy to POC server
  push portal          Push portal image to registry

Components:
  portal               Build portal image for cloud
  backend              Build ada_backend (local)
  engine               Build ada_engine (local)
  scanner              Build ada_scanner (local)
  zeek                 Build ada_zeek (local)
  kibana               Build ada_kibana (local)
  elasticsearch        Build ada_elasticsearch (local)
  elasticsearch-setup  Build ada_elasticsearch_setup (local)
  local                Build all local images
  all                  Build all local images + portal
  poc                  Deploy local images to POC server (skip ES/Kibana)
  all                  Deploy local images to POC server (include ES/Kibana)

Examples:
  $0 build local
  $0 build portal
  $0 build all
  $0 package backend
  $0 deploy backend
  $0 release backend
  $0 deploy poc
  $0 deploy all
  $0 push portal
EOF
}

main() {
    assert_paths

    case "${1:-}" in
        build)
            case "${2:-}" in
                portal)
                    build_portal
                    ;;
                backend|engine|scanner|zeek|kibana|elasticsearch|elasticsearch-setup)
                    build_local_component "${2}"
                    ;;
                local|"")
                    build_local_all
                    ;;
                all)
                    build_local_all
                    build_portal
                    ;;
                *)
                    usage
                    exit 1
                    ;;
            esac
            ;;
        package)
            case "${2:-}" in
                backend|engine|scanner|zeek|kibana|elasticsearch|elasticsearch-setup|all)
                    package_local_component "${2}"
                    ;;
                *)
                    usage
                    exit 1
                    ;;
            esac
            ;;
        deploy)
            case "${2:-}" in
                backend|engine|scanner|zeek|kibana|elasticsearch|elasticsearch-setup)
                    deploy_service "${2}"
                    ;;
                poc|"")
                    deploy_all true
                    ;;
                all)
                    deploy_all false
                    ;;
                *)
                    usage
                    exit 1
                    ;;
            esac
            ;;
        release)
            case "${2:-}" in
                backend|engine|scanner|zeek|kibana|elasticsearch|elasticsearch-setup)
                    build_local_component "${2}"
                    package_local_component "${2}"
                    deploy_service "${2}"
                    ;;
                poc|"")
                    build_local_all
                    package_local_component all
                    deploy_all true
                    ;;
                all)
                    build_local_all
                    package_local_component all
                    deploy_all false
                    ;;
                *)
                    usage
                    exit 1
                    ;;
            esac
            ;;
        push)
            case "${2:-}" in
                portal)
                    push_portal
                    ;;
                *)
                    usage
                    exit 1
                    ;;
            esac
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
