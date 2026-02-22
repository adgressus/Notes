
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


### Debuging notes
- Functions compiled for the wrong platform (rust target) fail siliently in a Azure Function (they don't start so all the logging is from the worker process)
- default api path is api/[foldername]