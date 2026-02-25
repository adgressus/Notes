#!/bin/bash
set -eu

[[ "$(uname)" == "Darwin" ]] || { echo "macOS required" >&2; exit 1; }

USER_ID=$(uuidgen)
TIMESTAMP=$(date +%s)

az storage entity insert \
  --account-name notesauthstorage \
  --table-name users \
  --entity PartitionKey=user RowKey="$USER_ID" created_at="$TIMESTAMP"

echo "User created with ID:"
echo "$USER_ID"
