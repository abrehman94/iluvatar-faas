function_container="docker.io/aarehman/chameleon-iluvatar-action:latest"
input_file="../functions/chameleon/input.json"

function_container="docker.io/aarehman/010.sleep-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/000.microbenchmarks/010.sleep/python/input.json"

function_container="docker.io/aarehman/030.clock-synchronization-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/000.microbenchmarks/030.clock-synchronization/python/input.json"

function_container="docker.io/aarehman/040.server-reply-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/000.microbenchmarks/040.server-reply/python/input.json"

function_container="docker.io/aarehman/110.dynamic-html-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/100.webapps/110.dynamic-html/python/input.json"

function_container="docker.io/aarehman/120.uploader-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/100.webapps/120.uploader/python/input.json"

function_container="docker.io/aarehman/210.thumbnailer-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/200.multimedia/210.thumbnailer/python/default_input.json"

function_container="docker.io/aarehman/220.video-processing-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/200.multimedia/220.video-processing/python/default_input.json"

function_container="docker.io/aarehman/311.compression-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/300.utilities/311.compression/python/default_input.json"

function_container="docker.io/aarehman/411.image-recognition-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/400.inference/411.image-recognition/python/default_input.json"

function_container="docker.io/aarehman/501.graph-pagerank-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/500.scientific/501.graph-pagerank/python/default_input.json"

function_container="docker.io/aarehman/502.graph-mst-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/500.scientific/502.graph-mst/python/default_input.json"

function_container="docker.io/aarehman/503.graph-bfs-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/500.scientific/503.graph-bfs/python/default_input.json"

function_container="docker.io/aarehman/504.dna-visualisation-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/500.scientific/504.dna-visualisation/python/default_input.json"

function_container="docker.io/aarehman/020.network-benchmark-iluvatar-action:latest"
input_file="../sebs-functions/benchmarks/000.microbenchmarks/020.network-benchmark/python/default_input.json"

minio_image="minio/minio:RELEASE.2025-09-07T16-13-09Z-cpuv1"
minio_address="127.0.0.1:9000"
minio_address="172.29.200.220:9000"
minio_access_key="minioadmin"
minio_secret_key="minioadmin"

docker_run_cmd=$(
	cat <<EOF
docker run \
	--rm \
	-it \
	-p 8000:8000 \
	-p 9010:9010/udp \
    --env=GUNICORN_CMD_ARGS=--bind=0.0.0.0:8000 \
	--env=MINIO_ADDRESS=$minio_address \
	--env=MINIO_ACCESS_KEY=$minio_access_key \
	--env=MINIO_SECRET_KEY=$minio_secret_key 
EOF
)
