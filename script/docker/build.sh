
version=2.9.1
root_path="/home/adadmin/adaegis"
ada_path="${root_path}/ada"
web_path="${root_path}/ada-web"

remote_server="adadmin@192.168.7.2"

# build path
# 统一规范： 该脚本在当前目录下执行，不可以在每个docker 子目录下运行

# build engine
build_engine() {
    cd engine || exit;
    cp ${ada_path}/bin/engine ./
    cp ${ada_path}/bin/engine.yaml ./
    sed -i "s/version=.*/version=${version}/g" Dockerfile
    docker build --network=host -f Dockerfile -t ada_engine:${version} .
    cd - || exit
}

# build frontend
build_frontend() {
    cd ${web_path} || exit;
    npm run build
    rm -rf ${ada_path}/script/docker/backend/static
    cp -r ${web_path}/dist ${ada_path}/script/docker/backend/static
    cd - || exit
}

# build backend
build_backend() {
    cd backend || exit;
    cp ${ada_path}/agent/script/adaegis.zip ./
    cp ${ada_path}/agent/script/install-adaegis.ps1 ./
    cp ${ada_path}/agent/script/uninstall-adaegis.ps1 ./
    cp ${ada_path}/bin/apiserver ./
    cp ${ada_path}/bin/task_server ./
    cp ${ada_path}/bin/task_worker ./
    cp ${ada_path}/bin/tasker.yaml ./
    cp ${ada_path}/bin/apiserver.yaml ./
    sed -i "s/version=.*/version=${version}/g" Dockerfile
    docker build --network=host -f Dockerfile -t ada_backend:${version} .
    cd - || exit
}

# build scanner
build_scanner() {
    cd scanner || exit;
    cp ${ada_path}/bin/scanner ./
    cp ${ada_path}/bin/scanner.yaml ./
    sed -i "s/version=.*/version=${version}/g" Dockerfile
    docker build --network=host -f Dockerfile -t ada_scanner:${version} .
    cd - || exit
}

# build zeek
build_zeek() {
    cd zeek || exit;
    docker build --network=host -f Dockerfile -t ada_zeek:${version} .
    cd - || exit
}

# build redis
build_redis() {
    cd redis || exit;
    docker build --network=host -f Dockerfile -t ada_redis:${version} .
    cd - || exit
}

# build mongodb
build_mongodb() {
    cd mongodb || exit;
    sed -i "s/ADA_SERVER_VERSION/${version}/g" 02-init_db.js
    docker build --network=host -f Dockerfile -t ada_mongodb:${version} .
    cd - || exit
}

#build kibana
build_kibana() {
    cd kibana || exit;
    docker build --network=host -f Dockerfile -t ada_kibana:${version} .
    cd - || exit
}

# build elasticsearch
build_elasticsearch() {
    cd elasticsearch || exit;
    docker build --network=host -f Dockerfile -t ada_elasticsearch:${version} .
    cd - || exit
}

build_images() {
    case $1 in
    engine)
        build_engine
        ;;
    frontend)
        build_frontend
        ;;
    backend)
        build_backend
        ;;
    scanner)
        build_scanner
        ;;
    zeek)
        build_zeek
        ;;
    redis)
        build_redis
        ;;
    mongodb)
        build_mongodb
        ;;
    kibana)
        build_kibana
        ;;
    elasticsearch)
        build_elasticsearch
        ;;
    all)
        build_engine
        build_backend
        build_scanner
        build_zeek
        build_redis
        build_mongodb
        build_kibana
        build_elasticsearch
        ;;
    *)
        echo "Usage: $0 {engine|backend|scanner|zeek|redis|mongodb|kibana|elasticsearch|all}"
        exit 1
        ;;
    esac
}

package_images() {
    case $1 in
        backend)
            docker save -o ada_backend_${version}.tar ada_backend:${version}
            ls -l ada_backend_${version}.tar
            ;;
        engine)
            docker save -o ada_engine_${version}.tar ada_engine:${version}
            ls -l ada_engine_${version}.tar
            ;;
        scanner)
            docker save -o ada_scanner_${version}.tar ada_scanner:${version}
            ls -l ada_scanner_${version}.tar
            ;;
        zeek)
            docker save -o ada_zeek_${version}.tar ada_zeek:${version}
            ls -l ada_zeek_${version}.tar
            ;;
        redis)
            docker save -o ada_redis_${version}.tar ada_redis:${version}
            ls -l ada_redis_${version}.tar
            ;;
        mongodb)
            docker save -o ada_mongodb_${version}.tar ada_mongodb:${version}
            ls -l ada_mongodb_${version}.tar
            ;;
        kibana)
            docker save -o ada_kibana_${version}.tar ada_kibana:${version}
            ls -l ada_kibana_${version}.tar
            ;;
        elasticsearch)
            docker save -o ada_elasticsearch_${version}.tar ada_elasticsearch:${version}
            ls -l ada_elasticsearch_${version}.tar
            ;;
        all)
            docker save -o ada_engine_${version}.tar ada_engine:${version}
            docker save -o ada_backend_${version}.tar ada_backend:${version}
            docker save -o ada_scanner_${version}.tar ada_scanner:${version}
            docker save -o ada_zeek_${version}.tar ada_zeek:${version}
            docker save -o ada_redis_${version}.tar ada_redis:${version}
            docker save -o ada_mongodb_${version}.tar ada_mongodb:${version}
            docker save -o ada_kibana_${version}.tar ada_kibana:${version}
            docker save -o ada_elasticsearch_${version}.tar ada_elasticsearch:${version}
            ls -l ada_elasticsearch_${version}.tar
            ls -l ada_engine_${version}.tar
            ls -l ada_backend_${version}.tar
            ls -l ada_scanner_${version}.tar
            ls -l ada_zeek_${version}.tar
            ls -l ada_redis_${version}.tar
            ls -l ada_mongodb_${version}.tar
            ls -l ada_kibana_${version}.tar
            ;;
    esac
}

deploy_service() {
    cd ${ada_path}/script/docker || exit
    case $1 in
        backend)
            echo "Deploying ada_backend:${version}..."
            scp ada_backend_${version}.tar ${remote_server}:/tmp/
            ssh ${remote_server} "cd /home/adadmin/ && docker compose down ada_backend"
            ssh ${remote_server} "docker rmi -f ada_backend:${version} 2>/dev/null || true"
            ssh ${remote_server} "docker load -i /tmp/ada_backend_${version}.tar"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose up -d ada_backend"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose ps ada_backend"
            ssh ${remote_server} "rm -f /tmp/ada_backend_${version}.tar"
            echo "Deployment completed."
            ;;
        engine)
            echo "Deploying ada_engine:${version}..."
            scp ada_engine_${version}.tar ${remote_server}:/tmp/
            ssh ${remote_server} "cd /home/adadmin/ && docker compose down ada_engine"
            ssh ${remote_server} "docker load -i /tmp/ada_engine_${version}.tar"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose up -d ada_engine"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose ps ada_engine"
            ssh ${remote_server} "rm -f /tmp/ada_engine_${version}.tar"
            echo "Deployment completed."
            ;;
        scanner)
            echo "Deploying ada_scanner:${version}..."
            scp ada_scanner_${version}.tar ${remote_server}:/tmp/
            ssh ${remote_server} "cd /home/adadmin/ && docker compose down ada_scanner"
            ssh ${remote_server} "docker load -i /tmp/ada_scanner_${version}.tar"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose up -d ada_scanner"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose ps ada_scanner"
            ssh ${remote_server} "rm -f /tmp/ada_scanner_${version}.tar"
            echo "Deployment completed."
            ;;
        zeek)
            echo "Deploying ada_zeek:${version}..."
            scp ada_zeek_${version}.tar ${remote_server}:/tmp/
            ssh ${remote_server} "cd /home/adadmin/ && docker compose down ada_zeek"
            ssh ${remote_server} "docker load -i /tmp/ada_zeek_${version}.tar"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose up -d ada_zeek"
            ssh ${remote_server} "cd /home/adadmin/ && docker compose ps ada_zeek"
            ssh ${remote_server} "rm -f /tmp/ada_zeek_${version}.tar"
            echo "Deployment completed."
            ;;
        *)
            echo "Usage: $0 deploy {backend|engine|scanner|zeek}"
            exit 1
            ;;
    esac
}

main() {
    case $1 in
        build)
            build_images $2
            ;;
        package)
            package_images $2
            ;;
        deploy)
            deploy_service $2
            ;;
        *)
            echo "Usage: $0 {build [component]|package [component]|deploy [component]}"
            exit 1
            ;;
    esac
}


main $1 $2