# /data2/ar/worker_source/latest_source/iluvatar-faas/src/Ilúvatar/docs/examples/azure-trace

./generate-trace.sh

./azure/metadata-chosen-ecdf.csv
./azure/chosen-ecdf.csv

ps -aux | grep -i main.sh
pgrep -if main.sh | xargs kill -9
