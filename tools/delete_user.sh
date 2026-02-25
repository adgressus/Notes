#!/bin/bash
set -eu

[[ "$(uname)" == "Darwin" ]] || { echo "macOS required" >&2; exit 1; }

USER_ID="${1:?Usage: ./delete_user.sh <user_id>}"

az storage entity delete \
  --account-name notesauthstorage \
  --table-name users \
  --partition-key user \
  --row-key "$USER_ID"

echo "User deleted"
