Galachain Issuer

Run tunnel
```bash
ngrok http 3100
```

```bash
export AGENT_LABEL="Generic Issuer"
export DATABASE_TYPE="sqlite"
export SQLITE_PATH="sqlite2.db"
export EXTERNAL_URI=https://13b2b99758bb.ngrok.app
export ACCESS_TOKEN="xxxxxx"
export KMS_SECRET_KEY="d8a75cdd3c52b76bb44bd45d27c3d9aa19e13c349faffde7bd0ecd58bef0dd8e"

npm run start:dev:reload 

```


