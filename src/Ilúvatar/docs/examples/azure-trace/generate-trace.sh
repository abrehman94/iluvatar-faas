#!/bin/bash

venv_name="examples-venv"
if [ ! -d ./$venv_name ]; then
	python3 -m venv --clear $venv_name
	source ./$venv_name/bin/activate
	python3 -m pip install --upgrade pip --no-warn-script-location
	python3 -m pip install -r ../../../../load/reqs.txt --no-warn-script-location
	deactivate
fi

source ./$venv_name/bin/activate

azure_dir="azure"
mkdir -p $azure_dir
if [[ ! -f "$azure_dir/invocations_per_function_md.anon.d01.csv" ]]; then
	python3 ../../../../load/generation/azure/download.py --out-folder $azure_dir
fi

rm $azure_dir/chosen-ecdf.csv
rm $azure_dir/metadata-chosen-ecdf.csv
#python3 ../../../../load/generation/azure/ecdf_trace.py --out-folder $azure_dir --data-path $azure_dir --num-funcs 12 --duration 15 --seed 11
#python3 ../../../../load/generation/azure/ecdf_trace.py --out-folder $azure_dir --data-path $azure_dir --num-funcs 24 --duration 15 --seed 11
#python3 ../../../../load/generation/azure/ecdf_trace.py --out-folder $azure_dir --data-path $azure_dir --num-funcs 48 --duration 15 --seed 11

#python3 ../../../../load/generation/azure/ecdf_trace.py --out-folder $azure_dir --data-path $azure_dir --num-funcs 24 --duration 30 --seed 11
#python3 ../../../../load/generation/azure/ecdf_trace.py --out-folder $azure_dir --data-path $azure_dir --num-funcs 30 --duration 30 --seed 11
python3 ../../../../load/generation/azure/ecdf_trace.py --out-folder $azure_dir --data-path $azure_dir --num-funcs 36 --duration 30 --seed 11

deactivate
