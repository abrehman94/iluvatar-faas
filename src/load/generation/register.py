import argparse
from collections import defaultdict
import json
import subprocess
import os
from time import time
import numpy as np

argparser = argparse.ArgumentParser()
argparser.add_argument("--test", '-t')
argparser.add_argument("--clipth", '-c', default="/home/alex/repos/efaas/src/Ilúvatar/target/debug/iluvatar_worker_cli", required=False)
argparser.add_argument("--worker", '-w', default="local", required=False)

args = argparser.parse_args()

actions = os.listdir("../functions/python3/functions")

colds = defaultdict(list)
warms = defaultdict(list)

def register(args, version, dir):
  proc_args = [args.clipth, "--worker", args.worker, "--config", "/home/alex/repos/efaas/src/Ilúvatar/worker_cli/src/worker_cli.json", "register", "--name", dir, "--version", version, "--memory", "128", "--cpu", "1", "--image", image]
  cli = subprocess.run(args=proc_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  if cli.returncode != 0:
    print(cli.stderr)
    cli.check_returncode()

def invoke(args, version, dir):
  proc_args = [args.clipth, "--worker", args.worker, "--config", "/home/alex/repos/efaas/src/Ilúvatar/worker_cli/src/worker_cli.json", "invoke", "--name", dir, "--version", version]
  start = time()
  cli = subprocess.run(args=proc_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  end = time()
  duration = end - start
  if cli.returncode != 0:
    print(cli.stderr)
    cli.check_returncode()
  return cli, duration

for dir in actions:
  if dir in ["cnn_image_classification", "video_processing", "model_training", "image_processing", "json_dumps_loads"]:
    continue
  print(dir)
  image = "docker.io/alfuerst/{}-iluvatar-action:latest".format(dir)
  for i in range(10):
    version = "0.0.{}".format(i)
    register(args, version, dir)
    for _ in range(2):
      cli, duration = invoke(args, version, dir)
      try:
        output = json.loads(cli.stdout)
      except:
        print(cli.stdout)
        continue
      if "Error" in output:
        print(output["Error"])
        continue
      else:
        if "body" in output:
          if "cold" in output["body"]:
            if bool(output["body"]["cold"]):
              colds[dir].append(duration)
            else:
              warms[dir].append(duration)

for k in colds.keys():
  print(k, np.mean(warms[k]), np.mean(colds[k]))
