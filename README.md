

### Clouds
* Azure
* (planned) GCP
* (planned) AWS

### Functions
* get_nonce
* get_token


### Tables
#### users
| PartitionKey | RowKey   | Timestamp   |
| ------------ | -------- | ----------- |
| 'users'      | *UUIDv4* | *ISO 8601*  |

#### linkingcodes
| PartitionKey    | RowKey           | Timestamp   | user_id     | created_at    | expires_at    |
| --------------- | ---------------- | ----------- | ----------- | ------------- | ------------- |
| 'linking_codes' | *six digit code* | *ISO 8601*  | *UUIDv4*\*  | *unix Epoch*  | *unix Epoch*  |

\* Foreign Key: users

#### nonces
| PartitionKey | RowKey          | Timestamp   | user_id     | created_at    | expires_at    |
| ------------ | --------------- | ----------- | ----------- | ------------- | ------------- |
| 'nonce'      | *64 char nonce* | *ISO 8601*  | *UUIDv4*\*  | *unix Epoch*  | *unix Epoch*  |

\* Foreign Key: users

#### linkedaccounts
| PartitionKey      | RowKey                       | Timestamp   | account_provider | user_id     | created_at    |
| ----------------- | ---------------------------- | ----------- | ---------------- | ----------- | ------------- |
| 'linked_accounts' | *'sub' field from JWT token* | *ISO 8601*  | *string*         | *UUIDv4*\*  | *unix Epoch*  |

\* Foreign Key: users

#### sessions
| PartitionKey | RowKey                   | Timestamp  | user_id    | created_at    | expires_at    |
| ------------ | ------------------------ | ---------- | ---------- | ------------- | ------------- |
| 'sessions'   | *128 char refresh token* | *ISO 8601* | *UUIDv4*\* | *unix Epoch*  | *unix Epoch*  |

\* Foreign Key: users