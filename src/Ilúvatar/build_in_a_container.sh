#!/bin/bash

populate_script_path() {
    SCRIPT_PATH=$(dirname $1)
    SCRIPT_PATH=$(realpath $SCRIPT_PATH)
}
if [[ $0 != $BASH_SOURCE ]]; then
    populate_script_path $BASH_SOURCE
else
    populate_script_path $0
fi
ORIGINAL_PATH=$(pwd)
cd $SCRIPT_PATH

## Build current folder in a debian image 
#if false; then 
if true; then 
    docker build          \
        --network host        \
        -t make-runner        \
        -f ./Dockerfile.build \
        ./
fi

cmd=$1
docker run                                 \
    --rm                                       \
    -it                                        \
    -v "$PWD":/workspace                       \
    -v "/home/abrehman/workspace/scx/scx":/scx \
    -w /workspace                              \
    --network host                             \
    make-runner  $cmd                             
#    make-runner                                \
#    /bin/bash 



