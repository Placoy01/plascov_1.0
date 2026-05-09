#!/bin/bash

# PLASCOV Security Framework - Easy Launcher
# This script makes running PLASCOV easier

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$SCRIPT_DIR/plascoy_env"

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    echo "Error: Virtual environment not found at $VENV_PATH"
    echo "Please run: python3 -m venv $VENV_PATH"
    exit 1
fi

# Activate virtual environment
source "$VENV_PATH/bin/activate"

# Run plascoy with all arguments passed to this script
python3 "$SCRIPT_DIR/plascoy.py" "$@"
