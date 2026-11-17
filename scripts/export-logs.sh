#!/usr/bin/env bash

# ==============================================================================
# Script Name: podmanexportlogs.sh
# Description: Exports Suricata logs from a Podman container and fixes ownership.
# ==============================================================================

# Script name variable for dynamic help messages
SCRIPT_NAME="$(basename "$0")"

# Check for help flags
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Usage Options:"
    echo "  $SCRIPT_NAME <container_name_or_id> [destination_path]"
    echo ""
    echo "Examples:"
    echo "  # Copies to your current directory"
    echo "  $SCRIPT_NAME my-suricata-container"
    echo ""
    echo "  # Copies to a specific custom directory"
    echo "  $SCRIPT_NAME my-suricata-container ~/workspace/suricata-analysis/"
    exit 0
fi

# Validate arguments
if [[ -z "$1" ]]; then
    echo "Error: Please provide the Podman container name or ID." >&2
    echo "Type '$SCRIPT_NAME --help' for examples." >&2
    exit 1
fi

CONTAINER="$1"
DEST="${2:-.}"
SRC_PATH="/var/log/suricata/"

# Ensure destination directory exists if a custom path was provided
if [[ ! -d "$DEST" ]]; then
    mkdir -p "$DEST" || {
        echo "Error: Failed to create destination directory: $DEST" >&2
        exit 1
    }
fi

echo "Fetching logs from '$CONTAINER'..."

# Run podman cp
if podman cp "${CONTAINER}:${SRC_PATH}" "$DEST"; then
    echo ""
    echo "Successfully copied suricata logs to: $(realpath "$DEST")"

    # Give ownership to nonroot users  
    TARGET_DIR="${DEST%/}/suricata"

    if [[ -d "$TARGET_DIR" ]]; then
        echo "Adjusting permissions for $TARGET_DIR..."
        chmod -R 775 "$TARGET_DIR"
        chown -R kim:kim "$TARGET_DIR"
        echo "Done granting access to nonroot users."
    fi
else
    echo "Error: Failed to copy logs. Please check if the container name is correct and running." >&2
    exit 1
fi

exit 0

