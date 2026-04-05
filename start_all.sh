#!/bin/bash
echo "Starting Distributed Component Architecture..."

# Start the node registry & monitor server in background
python collector/server.py &
SERVER_PID=$!

# Wait for server to come up
sleep 3

# Start two nodes in the same container/machine instance
python agents/simulator.py Node-A 10 &
NODE_A_PID=$!

python agents/simulator.py Node-B 5 &
NODE_B_PID=$!

# Bind all process terminations safely
trap "kill -9 $SERVER_PID $NODE_A_PID $NODE_B_PID" SIGINT SIGTERM

echo "All components running!"
# Wait for long-lived processes
wait
