#!/bin/sh

LEADER_BIN="./bin/debug_x64/leader_node"
CLIENT_BIN="./bin/debug_x64/client_node"
TERMINAL="st"

PEER_BASE=7000
CLIENT_BASE=8000
NUM_LEADERS=4

echo "Generating TLS certificates and signing keys..."

for i in $(seq 0 $((NUM_LEADERS-1))); do
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout node_${i}.key \
        -out node_${i}.crt \
        -days 365 -subj "/CN=leader${i}" 2>/dev/null

    openssl rsa -in node_${i}.key -pubout -out node_${i}.pub 2>/dev/null
done

cp node_0.crt cert.pem
cp node_0.key key.pem


# ------------------------------------------------
# Build port lists
# ------------------------------------------------

PEER_PORTS=""
CLIENT_PORTS=""

i=0
while [ $i -lt $NUM_LEADERS ]; do
    PEER_PORTS="$PEER_PORTS $((PEER_BASE+i))"
    CLIENT_PORTS="$CLIENT_PORTS $((CLIENT_BASE+i))"
    i=$((i+1))
done

echo "Leader peer ports:$PEER_PORTS"
echo "Leader client ports:$CLIENT_PORTS"


# ------------------------------------------------
# Launch leaders
# ------------------------------------------------

i=0
for PEER_PORT in $PEER_PORTS; do

    CLIENT_PORT=$(echo $CLIENT_PORTS | cut -d' ' -f$((i+1)))

    PEERS=""

    j=0
    for P in $PEER_PORTS; do
        if [ $j -ne $i ]; then
            PEERS="$PEERS$P,"
        fi
        j=$((j+1))
    done

    PEERS=$(echo "$PEERS" | sed 's/,$//')

    echo "Launching leader $i"
    echo "  peer_port   = $PEER_PORT"
    echo "  client_port = $CLIENT_PORT"
    echo "  peers       = $PEERS"

    $TERMINAL -T "Leader $i" -e sh -c "$LEADER_BIN $i $PEER_PORT $CLIENT_PORT $PEERS" &

    sleep 0.5
    i=$((i+1))
done


sleep 6


# ------------------------------------------------
# Launch client
# ------------------------------------------------

CLIENT_CSV=$(echo $CLIENT_PORTS | tr ' ' ',')

echo "Launching client"
echo "  leaders = $CLIENT_CSV"

$TERMINAL -T "Client" -e sh -c "$CLIENT_BIN $CLIENT_CSV" &


sleep 200

echo "Stopping test..."
kill $(jobs -p) 2>/dev/null
echo "Done."
