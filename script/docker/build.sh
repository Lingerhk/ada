
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
    docker build --network=host -f Dockerfile -t ada_engine:${version} .
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

package_images() {
    echo "package images:"
    echo "packing ada_engine:${version}.tar"
    docker save -o ada_engine:${version}.tar ada_engine:${version}
    echo "packing ada_backend:${version}.tar"
    docker save -o ada_backend:${version}.tar ada_backend:${version}
    echo "packing ada_scanner:${version}.tar"
    docker save -o ada_scanner:${version}.tar ada_scanner:${version}
    echo "packing ada_zeek:${version}.tar"
    docker save -o ada_zeek:${version}.tar ada_zeek:${version}
    echo "packing ada_redis:${version}.tar"
    docker save -o ada_redis:${version}.tar ada_redis:${version}
    echo "packing ada_mongodb:${version}.tar"
    docker save -o ada_mongodb:${version}.tar ada_mongodb:${version}
    echo "packing ada_kibana:${version}.tar"
    docker save -o ada_kibana:${version}.tar ada_kibana:${version}
    echo "packing ada_elasticsearch:${version}.tar"
    docker save -o ada_elasticsearch:${version}.tar ada_elasticsearch:${version}
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
        package)
            package_images
            ;;
        *)
            echo "Usage: $0 {engine|backend|scanner|zeek|redis|mongodb|kibana|elasticsearch|all|package}"
            exit 1
            ;;
    esac
}


main $1