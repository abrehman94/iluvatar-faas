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

source ./config.sh

curl \
	--data-binary @"$input_file" \
	-H "Content-Type: application/json" \
	http://localhost:8000/invoke
