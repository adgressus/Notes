#!/bin/bash
set -eu

[[ "$(uname)" == "Darwin" ]] || { echo "macOS required" >&2; exit 1; }

USER_ID="${1:?Usage: ./create_link_code.sh <user_id>}"
LINK_CODE="$(jot -r 1 0 999999 | xargs printf '%06d')"
TIMESTAMP="$(date +%s)"
EXPIRES_AT="$(( TIMESTAMP + 300 ))"

az storage entity insert \
  --account-name notesauthstorage \
  --table-name linkingcodes \
  --entity PartitionKey=link_code RowKey="$LINK_CODE" user_id="$USER_ID" created_at="$TIMESTAMP" created_at@odata.type=Edm.Int64 expires_at="$EXPIRES_AT" expires_at@odata.type=Edm.Int64

echo "Link code (expires in 5 minutes):"
echo "$LINK_CODE"
