#!/bin/bash
# Multi-core Isolated Primaries model (Scale linearly with isolated links)
# Server $i <-> Client $i on Socket $i

docker exec my-ubuntu pkill -9 perf_tool
docker exec my-ubuntu rm -rf /var/run/dpdk/* /tmp/memif_*.sock
rm -f s*.log c*.log

TOTAL_CORES=2

# 1. Start Servers
for i in $(seq 0 $((TOTAL_CORES-1))); do
    echo "Starting Server Core $i..."
    docker exec -d -w /app my-ubuntu bash -c "./build_container/perf_tool --proc-id $i --total-procs $TOTAL_CORES server /app/perf_tool/example/memif/multi_core/server.json > s$i.log 2>&1"
done

sleep 5

# 2. Start Clients
for i in $(seq 0 $((TOTAL_CORES-1))); do
    echo "Starting Client Core $i..."
    docker exec -d -w /app my-ubuntu bash -c "./build_container/perf_tool --proc-id $i --total-procs $TOTAL_CORES client /app/perf_tool/example/memif/multi_core/client.json > c$i.log 2>&1"
done

echo "Checking status..."
sleep 15
docker exec my-ubuntu ps aux | grep perf_tool
