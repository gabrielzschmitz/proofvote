#!/bin/sh
# run_test.sh
# Launch 4 leader nodes and 1 client node for ProofVote test

LEADER_BIN="./bin/debug_x64/leader_node"
CLIENT_BIN="./bin/debug_x64/client_node"
TERMINAL="st"

BASE_PORT=7000
NUM_LEADERS=4

# --- Build leader ports ---
PORTS=""
i=0
while [ $i -lt $NUM_LEADERS ]; do
    PORTS="$PORTS $((BASE_PORT + i))"
    i=$((i + 1))
done

# --- Spawn leader nodes ---
i=0
for PORT in $PORTS; do
    # Build peer CSV (exclude own port)
    PEERS=""
    for P in $PORTS; do
        [ "$P" != "$PORT" ] && PEERS="$PEERS$P,"
    done
    PEERS=$(echo "$PEERS" | sed 's/,$//')

    echo "Launching leader $i on port $PORT with peers $PEERS"

    # Start each leader in its own terminal
    $TERMINAL -T "Leader $i" -e sh -c "$LEADER_BIN $i $PORT $PEERS" &

    # Small delay to avoid connection race
    sleep 0.5
    i=$((i + 1))
done

# --- Wait for leaders to start listening ---
sleep 3

# --- Spawn client node ---
LEADER_CSV=$(echo $PORTS | tr ' ' ',')
echo "Launching client node connected to leaders at ports $LEADER_CSV"

$TERMINAL -T "Client" -e sh -c "$CLIENT_BIN $LEADER_CSV" &

# --- Wait for test to run ---
sleep 200

# --- Kill all processes ---
echo "Test finished. Killing all leader and client nodes..."
kill $(jobs -p) 2>/dev/null
echo "Done."
