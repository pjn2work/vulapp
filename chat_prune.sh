#!/bin/bash
# Remove expired chat messages, empty chats and expired tokens from chat_store.json.
# Runs from this script's directory, where `python run.py` creates chat_store.json.
# Override the interpreter with PYTHON=/path/to/python ./chat_prune.sh
set -e
cd "$(dirname "$0")"

if [ -z "$PYTHON" ]; then
    if [ -x .venv/bin/python ]; then
        PYTHON=.venv/bin/python
    else
        PYTHON=python3
    fi
fi

exec "$PYTHON" -m vulapp.chat_store prune
