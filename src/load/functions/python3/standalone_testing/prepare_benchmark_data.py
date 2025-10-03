#!/usr/bin/env python3

import fire
import os
import shutil
from storage import storage
import json

os.environ['MINIO_ADDRESS'] = "172.29.200.220:9000"
os.environ['MINIO_ACCESS_KEY'] = "minioadmin"
os.environ['MINIO_SECRET_KEY'] = "minioadmin"


def CollectPaths(base_path, last_node):

    collected_paths = []
    for local_node in os.listdir(base_path):
        local_node_path = os.path.join(base_path, local_node)
        if local_node == last_node:
            collected_paths.append(local_node_path)
        elif os.path.isdir(local_node_path):
            collected_paths.extend(CollectPaths(local_node_path, last_node))

    return collected_paths


def UploadToStorage(bucket_idx, key, filepath):
    client = storage.get_instance()
    client.upload(bucket_names[bucket_idx], key, filepath)


def PrepareBenchmark(function_path, data_path):
    function_dir = os.path.dirname(function_path)
    input_path = os.path.join(function_dir, '../input.py')
    default_input_config_path = os.path.join(
        function_dir, 'default_input.json')

    bucket_name = function_dir.split('/')[-2]
    # Used by UploadToStorage
    global bucket_names
    bucket_names = {
        0: bucket_name,
        1: bucket_name
    }

    input_paths = ["", ""]
    output_paths = ["exp1"]

    with open(input_path, 'r') as input_file:
        source = input_file.readlines()
        code_object = compile("".join(source), input_path, 'exec')
        exec(code_object, locals())

        input_config = eval("generate_input(data_path, size='small', benchmarks_bucket=bucket_name, input_paths=input_paths, output_paths=output_paths, upload_func=UploadToStorage, nosql_func=None)",
                            globals(), locals())

        json.dump(input_config, open(default_input_config_path, 'w'), indent=4)


def BenchmarkPathToDataPath(benchmark_path):
    nodes = benchmark_path.split('/')[:-2]
    nodes = ['benchmarks-data' if node ==
             'benchmarks' else node for node in nodes]
    return '/'.join(nodes)


def main(benchmark_path="../sebs-functions/benchmarks", benchmark_data_path="../sebs-functions/benchmarks-data"):

    script_path = os.path.dirname(__file__)

    benchmark_path = os.path.realpath(
        os.path.join(script_path, benchmark_path))
    benchmark_data_path = os.path.realpath(
        os.path.join(script_path, benchmark_data_path))

    benchmarks = CollectPaths(benchmark_path, 'function.py')
    # benchmarks = ['/data2/ar/worker_source/iluvatar-faas/src/load/functions/python3/sebs-functions/benchmarks/500.scientific/504.dna-visualisation/python/function.py']

    benchmarks_data = list(map(BenchmarkPathToDataPath, benchmarks))

    list(map(PrepareBenchmark, benchmarks, benchmarks_data))


if __name__ == "__main__":
    fire.Fire(main)
