#!/bin/bash
set -eu

[[ "$(uname)" == "Darwin" ]] || { echo "macOS required" >&2; exit 1; }

NOW=$(date +%s)
COUNT=0

ENTITIES=$(az storage entity query \
  --account-name notesauthstorage \
  --table-name linkingcodes \
  --filter "PartitionKey eq 'link_code' and expires_at lt ${NOW}L" \
  --output json)

for ROW_KEY in $(echo "$ENTITIES" | jq -r '.items[].RowKey'); do
  az storage entity delete \
    --account-name notesauthstorage \
    --table-name linkingcodes \
    --partition-key link_code \
    --row-key "$ROW_KEY" \
    --output none
  COUNT=$((COUNT + 1))
done

if [[ $COUNT -eq 1 ]]; then
  echo "1 expired code deleted"
else
  echo "$COUNT expired codes deleted"
fi
