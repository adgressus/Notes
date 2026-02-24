# Tools
Tooling is currently macos only, though commands should work with minimal, possibly no changes on linux

#### Setup
- make script executable before trying to run them
```
chmod +x *.sh
```
- login to Azure
```
az login
```

#### Scripts
- Add new user, returns user's UUID
```
./add_user.sh
```
- (not implemented) `delete_user.sh`
- Create code to link user to authenticator account
```
./create_link_code.sh <paste user UUID>
```
- (not implemented) `list_users.sh`