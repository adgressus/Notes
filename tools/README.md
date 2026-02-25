# Tools
Tooling is currently macos only. Though commands should work with minimal, possibly no changes on linux

#### Setup
- login to Azure
```
az login
```

#### Scripts
- Add new user, returns user's UUID
```
./add_user.sh
```
- Delete user
```
./delete_user.sh <paste user UUID>
```
- Create code to link user to authenticator account
```
./create_link_code.sh <paste user UUID>
```
- (not implemented) `list_users.sh`
- Delete all expired linking codes
```
./clear_expired_codes.sh
```
- (not implemented) `show_table_sizes.sh`