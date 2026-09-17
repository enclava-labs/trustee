#!/usr/bin/env bash
# Disposable PostgreSQL TLS harness. Uses only local temporary clusters
# and synthetic credentials; removes both clusters when the command exits.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PGBIN="${PGBIN:-$(pg_config --bindir)}"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/trustee.tls.XXXXXX")
read -r PORT_A PORT_B < <(python3 - <<'PY'
import socket
with socket.socket() as a, socket.socket() as b:
    a.bind(("127.0.0.1", 0))
    b.bind(("127.0.0.1", 0))
    print(a.getsockname()[1], b.getsockname()[1])
PY
)
mkdir -p "$WORK/socket"
cleanup() {
  "$PGBIN/pg_ctl" -D "$WORK/pgdata-tls"  -m immediate stop >/dev/null 2>&1 || true
  "$PGBIN/pg_ctl" -D "$WORK/pgdata-plain" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- certificates (throwaway) --------------------------------------------
# Use ordinary dotted CA paths to catch URL parser regressions.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORK/ca-key" -out "$WORK/ca.crt" \
  -subj "/CN=TLS Regression CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORK/wrong-key" -out "$WORK/wrong-ca.crt" \
  -subj "/CN=Wrong CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/server-key" \
  -out "$WORK/server.csr" -subj "/CN=localhost" >/dev/null 2>&1
# SAN intentionally covers ONLY DNS:localhost (no IP entries) so that
# connecting via 127.0.0.1 fails verify-full hostname verification.
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca-key" \
  -CAcreateserial -days 2 -out "$WORK/server.crt" >/dev/null 2>&1 \
  -extfile <(printf 'subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
chmod 600 "$WORK/server-key"

# --- clusters -------------------------------------------------------------
for name in tls plain; do
  "$PGBIN/initdb" -D "$WORK/pgdata-$name" -U trustee --no-instructions >/dev/null
  cat > "$WORK/pgdata-$name/pg_hba.conf" <<'EOF'
local all all trust
host  all all 127.0.0.1/32 trust
host  all all ::1/128 trust
EOF
done
cat >> "$WORK/pgdata-tls/postgresql.conf" <<EOF
listen_addresses = 'localhost'
port = $PORT_A
unix_socket_directories = '$WORK/socket'
ssl = on
ssl_cert_file = '$WORK/server.crt'
ssl_key_file = '$WORK/server-key'
EOF
cat >> "$WORK/pgdata-plain/postgresql.conf" <<EOF
listen_addresses = 'localhost'
port = $PORT_B
unix_socket_directories = '$WORK/socket'
ssl = off
EOF
"$PGBIN/pg_ctl" -D "$WORK/pgdata-tls"   -l "$WORK/pg-tls.log"   -w start >/dev/null
"$PGBIN/pg_ctl" -D "$WORK/pgdata-plain" -l "$WORK/pg-plain.log" -w start >/dev/null

PSQL="$PGBIN/psql -h $WORK/socket -p $PORT_A -U trustee -d postgres -v ON_ERROR_STOP=1"
$PSQL -c 'CREATE DATABASE trustee' >/dev/null
$PSQL -d trustee -c 'CREATE TABLE kvs_tls_regression (key TEXT PRIMARY KEY, value BYTEA)' >/dev/null
$PSQL -d trustee -c 'CREATE TABLE key_value (value BYTEA, key TEXT PRIMARY KEY)' >/dev/null
$PSQL -d trustee -f "$REPO/kbs/test_data/sql/sessions.sql" >/dev/null

export POSTGRES_URL="postgresql://trustee@localhost:$PORT_A/trustee?sslmode=verify-full&sslrootcert=$WORK/ca.crt"
export POSTGRES_TLS_WRONG_CA_URL="postgresql://trustee@localhost:$PORT_A/trustee?sslmode=verify-full&sslrootcert=$WORK/wrong-ca.crt"
export POSTGRES_TLS_WRONG_HOST_URL="postgresql://trustee@127.0.0.1:$PORT_A/trustee?sslmode=verify-full&sslrootcert=$WORK/ca.crt"
export POSTGRES_TLS_NO_TLS_URL="postgresql://trustee@localhost:$PORT_B/trustee?sslmode=verify-full&sslrootcert=$WORK/ca.crt"
export CARGO_INCREMENTAL=0

echo "workdir=$WORK tls_port=$PORT_A plain_port=$PORT_B"
cd "$REPO"
if [ "$#" -eq 0 ]; then
  cargo test --locked -p key-value-storage --test postgres_tls -- --ignored
else
  "$@"
fi
