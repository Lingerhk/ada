#!/bin/bash

# ADAegis POC Deployment Script
# This script builds ada_service image and deploys to ClawCloud Run + POC server

set -e

version=2.9.1
root_path="/home/adadmin/adaegis"
ada_path="${root_path}/ada"
web_path="${root_path}/ada-web"
poc_path="${ada_path}/script/poc"
poc_service_path="${poc_path}/ada-service"

# POC server configuration
poc_server="adadmin@192.168.7.8"
poc_remote_path="/home/adadmin/ada-poc"

# Docker registry configuration
registry_url="docker.adaegis.net"
registry_user="adaegis"
registry_image="${registry_url}/ada_service:${version}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Build frontend
build_frontend() {
    log_info "Building frontend..."
    cd ${web_path} || exit
    npm run build
    rm -rf ${poc_service_path}/static
    cp -r ${web_path}/dist ${poc_service_path}/static
    log_info "Frontend build completed"
}

# Build backend binaries
build_backend() {
    log_info "Building backend binaries..."
    cd ${ada_path} || exit
    make apiserver task_server task_worker engine
    log_info "Backend binaries built"
}

# Prepare ada-service files
prepare_ada_service() {
    log_info "Preparing ada-service files..."
    cd ${poc_service_path} || exit

    # Copy backend binaries
    cp ${ada_path}/bin/apiserver ./
    cp ${ada_path}/bin/task_server ./
    cp ${ada_path}/bin/task_worker ./
    cp ${ada_path}/bin/engine ./

    # Copy sensor files
    cp ${ada_path}/agent/script/adaegis.zip ./
    cp ${ada_path}/agent/script/install-adaegis.ps1 ./
    cp ${ada_path}/agent/script/uninstall-adaegis.ps1 ./

    log_info "ada-service files prepared"
}

# Build ada_service Docker image
build_ada_service() {
    log_info "Building ada_service Docker image..."
    cd ${poc_service_path} || exit

    # Ensure IPv4 forwarding is enabled
    sudo sysctl net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # Build with host network for DNS resolution
    DOCKER_BUILDKIT=0 docker build --network=host -t ${registry_image} .

    log_info "Docker image built successfully: ${registry_image}"
}

# Push ada_service to registry
push_ada_service() {
    log_info "Pushing ada_service to registry..."

    # Login to registry
    echo "Please ensure you're logged in to ${registry_url}"
    docker push ${registry_image}

    log_info "Image pushed successfully to ${registry_url}"
}

# Deploy docker-compose to POC server
deploy_poc_server() {
    log_info "Deploying to POC server ${poc_server}..."

    # Check if POC server is accessible
    if ! ssh -o ConnectTimeout=5 ${poc_server} "echo 'Connection test'" >/dev/null 2>&1; then
        log_error "Cannot connect to POC server ${poc_server}"
        exit 1
    fi

    # Create remote directory if not exists
    ssh ${poc_server} "mkdir -p ${poc_remote_path}/logs"

    # Copy docker-compose.yml and frpc.ini
    log_info "Copying docker-compose.yml and frpc.ini to POC server..."
    scp ${poc_path}/docker-compose.yml ${poc_server}:${poc_remote_path}/

    # Pull/load required images on POC server
    log_info "Setting up Docker images on POC server..."

    # Check which images need to be loaded
    # Note: MongoDB and Redis use cloud services, not local containers
    images_needed=(
        "ada_elasticsearch:${version}"
        "ada_elasticsearch_setup:${version}"
        "ada_kibana:${version}"
        "ada_scanner:${version}"
    )

    for image in "${images_needed[@]}"; do
        log_info "Checking for image: ${image}"
        if ! ssh ${poc_server} "docker image inspect ${image} >/dev/null 2>&1"; then
            log_warn "Image ${image} not found on POC server. Please load it manually."
        fi
    done

    # Restart services
    log_info "Restarting services on POC server..."
    ssh ${poc_server} "cd ${poc_remote_path} && docker compose down || true"
    ssh ${poc_server} "cd ${poc_remote_path} && docker compose up -d"

    # Wait a bit for services to start
    sleep 5

    # Check service status
    log_info "Checking service status..."
    ssh ${poc_server} "cd ${poc_remote_path} && docker compose ps"

    log_info "POC server deployment completed"
}

# Show deployment status
show_status() {
    log_info "=== Deployment Status ==="
    echo ""
    echo "Local Docker Image:"
    docker images ${registry_image} --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
    echo ""

    if ssh -o ConnectTimeout=5 ${poc_server} "echo" >/dev/null 2>&1; then
        echo "POC Server Services:"
        ssh ${poc_server} "cd ${poc_remote_path} && docker compose ps" || true
    else
        log_warn "Cannot connect to POC server to check status"
    fi
}

# Display usage
usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
    build               Build frontend, backend, and Docker image
    push                Push Docker image to registry
    deploy              Deploy docker-compose to POC server
    full                Build, push, and deploy (full deployment)
    status              Show deployment status

Examples:
    $0 build                                    # Build everything
    $0 push                                     # Push to registry
    $0 deploy                                   # Deploy to POC server
    $0 full                                     # Complete deployment
    $0 status                                   # Show status

EOF
}

# Main execution
main() {
    case $1 in
        build)
            build_frontend
            build_backend
            prepare_ada_service
            build_ada_service
            log_info "Build completed successfully!"
            ;;
        push)
            push_ada_service
            log_info "Push completed successfully!"
            ;;
        deploy)
            deploy_poc_server
            log_info "Deployment completed successfully!"
            ;;
        full)
            build_frontend
            build_backend
            prepare_ada_service
            build_ada_service
            push_ada_service
            deploy_poc_server
            log_info "Full deployment completed successfully!"
            show_status
            ;;
        status)
            show_status
            ;;
        *)
            usage
            exit 1
            ;;  
    esac
}

# Check if running in POC directory
if [ ! -f "${poc_path}/build.sh" ]; then
    log_error "Please run this script from the POC directory"
    exit 1
fi

main "$@"
