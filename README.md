# bcr-court

Court Signature Verification reference implementation

## How to run 

```bash
just dev
```

OR

```bash
just watch
```

for restarts on change.

## Configuration

Local / Dev:

```
address = "0.0.0.0:8000"
domain = "127.0.0.1"
cookie_secure = false
log_level = "INFO"
db_user = "postgres"
db_password = "password"
db_name = ""
db_host = "localhost"
bitcoin_network = "testnet"
```

For production use, the actual `domain` needs to be set, `cookie_secure` needs to be set to `true` and
the `db_*` fields need to be set to the actual DB credentials.
