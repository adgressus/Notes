#!/bin/bash
set -euo pipefail

[[ -z "${VSCODE_ROOT:-}" ]] && { echo "VSCODE_ROOT is not set, are you running this script from the integrated terminal?" >&2; exit 1; }

cd "$VSCODE_ROOT/cloud/functions/code"

# Cross-compile for Linux (Azure Functions runtime)
cargo build --release --target x86_64-unknown-linux-musl

# Copy the binary to where the custom handler expects it
cp target/x86_64-unknown-linux-musl/release/handler handler

# Package everything into a zip file, excluding the contents of .funcignore
# funcignore uses zip glob patterns instead of gitignore syntax
zip -r function-app.zip . -x@.funcignore

# Deploy to Azure
az functionapp deployment source config-zip \
    --resource-group notes-auth-rg \
    --name notes-auth-func \
    --src function-app.zip

rm function-app.zip