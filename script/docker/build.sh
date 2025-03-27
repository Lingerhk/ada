
version=2.9.1
ada_path="/home/adadmin/github-ada"

# build path
# 统一规范： 该脚本在当前目录下执行，不可以在每个docker 子目录下运行

# build engine
build_engine() {
    cd engine || exit;
    cp ${ada_path}/bin/engine ./
    cp ${ada_path}/bin/engine.yaml ./
    sed -i "s/version=.*/version=${version}/g" Dockerfile
    docker build -f Dockerfile -t ada_engine:${version} .
    cd - || exit
}

# build backend
build_backend() {
    cd backend || exit;
    cp ${ada_path}/bin/apiserver ./
    cp ${ada_path}/bin/task_server ./
    cp ${ada_path}/bin/task_worker ./
    cp ${ada_path}/bin/tasker.yaml ./
    cp ${ada_path}/bin/apiserver.yaml ./
    sed -i "s/version=.*/version=${version}/g" Dockerfile
    docker build -f Dockerfile -t ada_backend:${version} .
    cd - || exit
}

# build scanner
build_scanner() {
    cd scanner || exit;
    cp ${ada_path}/bin/scanner ./
    cp ${ada_path}/bin/scanner.yaml ./
    sed -i "s/version=.*/version=${version}/g" Dockerfile
    docker build -f Dockerfile -t ada_scanner:${version} .
    cd - || exit
}

# build zeek
build_zeek() {
    cd zeek || exit;
    docker build -f Dockerfile -t ada_zeek:${version} .
    cd - || exit
}

# build redis
build_redis() {
    cd redis || exit;
    docker build -f Dockerfile -t ada_redis:${version} .
    cd - || exit
}

# build mongodb
build_mongodb() {
    cd mongodb || exit;
    # TODO: cp 02-init_db.js to docker/mongodb/02-init_db.js
    docker build -f Dockerfile -t ada_mongodb:${version} .
    cd - || exit
}

#build kibana
build_kibana() {
    cd kibana || exit;
    docker build -f Dockerfile -t ada_kibana:${version} .
    cd - || exit
}

# build elasticsearch
build_elasticsearch() {
    cd elasticsearch || exit;
    docker build -f Dockerfile -t ada_elasticsearch:${version} .
    cd - || exit
}


main() {
    case $1 in
        engine)
            build_engine
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


main $1