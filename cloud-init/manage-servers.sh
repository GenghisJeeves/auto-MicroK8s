#!/bin/bash
# filepath: /home/arww24/Documents/git/auto-MicroK8s/cloud-init/manage-servers.sh
# This script is used to manage the servers for the Auto MicroK8s Cluster.
# It assumes that Multipass is installed and configured on the system.
# Running the script without parameters will check the status of the servers.
# If the servers exist and are not running, it will start them.
# If the servers do not exist, it will create new instances.
# Running the script with the parameter "delete" will delete all MicroK8s servers.

# Define server names
SERVER_NAMES=("aw6-server1" "aw6-server2" "aw6-server3")

# Check if delete parameter was passed
if [ "$1" = "delete" ]; then
    echo "Deleting all MicroK8s servers..."
    for server in "${SERVER_NAMES[@]}"; do
        echo "Deleting $server..."
        multipass delete "$server"
    done
    echo "Purging deleted instances..."
    multipass purge
    echo "All servers deleted."
    exit 0
fi

# For each server, check its status and take appropriate action
for server in "${SERVER_NAMES[@]}"; do
    echo "Checking status of $server..."
    
    # Check if the server exists
    if ! multipass info "$server" &>/dev/null; then
        echo "Server $server does not exist. Creating new instance..."
        multipass launch --name "$server" --cpus 1 --memory 2G --disk 8G --cloud-init server.yaml --network br0
    else
        # Check the state of the server
        STATE=$(multipass info "$server" | grep "State:" | awk '{print $2}')
        
        if [ "$STATE" = "Running" ]; then
            echo "Server $server is already running."
        else
            echo "Starting server $server..."
            multipass start "$server"
        fi
    fi
done

echo
echo "Server status:"
multipass list