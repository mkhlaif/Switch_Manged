#!/usr/bin/env sh
# Create .env from .env.example with freshly generated secrets.
#
#   ./scripts/init-env.sh
#
# Generates POSTGRES_PASSWORD and CREDENTIAL_ENCRYPTION_KEY (Fernet key) with openssl.
# Never overwrites an existing .env. All other values keep the safe defaults of the template
# (READ_ONLY_MODE=true, NETWORK_COMMAND_EXECUTION=DISABLED); review .env afterwards.
set -eu
cd "$(dirname "$0")/.."

if [ -f .env ]; then
    echo ".env already exists; it was not modified." >&2
    exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required (Ubuntu: sudo apt install openssl)." >&2
    exit 1
fi

PG_PASSWORD="$(openssl rand -hex 24)"
FERNET_KEY="$(openssl rand -base64 32 | tr '+/' '-_')"

umask 077
sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PG_PASSWORD}|" \
    -e "s|^CREDENTIAL_ENCRYPTION_KEY=.*|CREDENTIAL_ENCRYPTION_KEY=${FERNET_KEY}|" \
    .env.example > .env

echo "Created .env with a generated database password and credential encryption key."
echo "Back up CREDENTIAL_ENCRYPTION_KEY securely: without it stored switch passwords are lost."
