# Set up build environment
rustup target add x86_64-unknown-linux-musl
brew install filosottile/musl-cross/musl-cross # macos c cross compiler. needed for rustls because c still has that special microcode magic


# Update infra
az deployment sub create \
  --location eastus2 \
  --template-file cloud/functions/infra/main.bicep \
  --parameters cloud/functions/infra/parameters.json

# Redeploy the entire function App
az functionapp deploy \
  --resource-group notes-auth-rg \
  --name notes-auth-func \
  --src-path function-app.zip \
  --type zip


## Kusto Help
```
traces
    | where severityLevel == 3
    | where cloud_RoleName == "notes-auth-func"
    | where timestamp > ago(1d)
    | project timestamp, message, operation_Name, customDimensions
    | order by timestamp desc
```

### Debuging notes
- Functions compiled for the wrong platform (rust target) fail siliently in a Azure Function (they don't start so all the logging is from the worker process)
- default api path is api/[foldername]

### Logging
- stdout will be ignored, log to stderr
- logs to stderr are automatically Error level to App Insights, regardless of the verbosity setting within the function
- pull all logs to stderr in the last day:
```
traces
    | where timestamp > ago(1d)
    | where cloud_RoleName == "notes-auth-func"
    | where customDimensions['Category'] == 'Host.Function.Console'
    | project timestamp, message, operation_Name, customDimensions
    | order by timestamp desc
```

### If this was a 'real' project:
- you might be using something other than rand for token generation since it doesn't make any prommises about being a crypto library