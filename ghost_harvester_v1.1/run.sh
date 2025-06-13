#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
# Name for the Docker image and container
IMAGE_NAME="ghost-harvester:latest"
CONTAINER_NAME="ghost-harvester"

# --- Host Paths ---
# !!! IMPORTANT: User must adjust these paths to match their environment !!!
# Path to WireGuard .conf files on the HOST machine
HOST_WG_CONFIGS_PATH="/opt/wg_nodes" # EXAMPLE: /etc/wireguard or /home/user/wg_configs

# Path on the HOST machine where persistent data (logs, downloaded corpus) will be stored
HOST_DATA_PATH="$(pwd)/data_host" # EXAMPLE: /srv/ghost_harvester_data or $(pwd)/data

# Path to the .env file on the HOST machine
HOST_DOT_ENV_PATH="$(pwd)/.env" # EXAMPLE: $(pwd)/.env or /etc/ghost_harvester/.env

# --- Script Logic ---

# Ensure the host data directory exists
echo "--- Ensuring host data directory exists at: $HOST_DATA_PATH ---"
mkdir -p "$HOST_DATA_PATH"
echo "--- Host data directory ready ---"

# Ensure the .env file exists
if [ ! -f "$HOST_DOT_ENV_PATH" ]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "ERROR: .env file not found at $HOST_DOT_ENV_PATH"
    echo "Please create it from .env.example and configure it before running this script."
    echo "Exiting."
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    exit 1
fi
echo "--- .env file found at: $HOST_DOT_ENV_PATH ---"

echo ""
echo "--- Building Docker image: $IMAGE_NAME ---"
# Assuming this script is run from the ghost_harvester_v1.1 directory
docker build -t "$IMAGE_NAME" .
echo "--- Docker image build complete ---"
echo ""

echo "--- Preparing to run Docker container: $CONTAINER_NAME ---"
echo "  WireGuard configs will be mounted from: $HOST_WG_CONFIGS_PATH"
echo "  Persistent data will be stored in: $HOST_DATA_PATH"
echo "  Environment variables will be loaded from: $HOST_DOT_ENV_PATH"
echo ""

# Check if container is already running and stop/remove it
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "--- Container '$CONTAINER_NAME' already exists. Stopping and removing... ---"
    docker stop "$CONTAINER_NAME" || true # Allow failure if already stopped
    docker rm "$CONTAINER_NAME" || true    # Allow failure if already removed
    echo "--- Existing container removed ---"
    sleep 2 # Give Docker a moment to release resources
fi

echo "--- Starting Docker container: $CONTAINER_NAME ---"
docker run -it --rm \
  --name "$CONTAINER_NAME" \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --device /dev/net/tun:/dev/net/tun \
  -v "$HOST_WG_CONFIGS_PATH":/etc/wireguard_configs:ro \
  -v "$HOST_DATA_PATH":/app/data \
  -v "$HOST_DOT_ENV_PATH":/app/.env:ro \
  "$IMAGE_NAME"

echo ""
echo "--- Container '$CONTAINER_NAME' exited ---"
