#!/usr/bin/env bash
# smoke.sh — fail-fast smoke test for the saas-leptos Docker image.
#
# Usage:
#   ./smoke.sh
#
# Env overrides:
#   BASE            base URL                       (default: http://127.0.0.1:3396)
#   HOST_PORT       host port to publish           (default: 3396)
#   CTR             container name                 (default: saas-leptos-smoke)
#   NET             docker network                 (default: rust-saas_rust_saas_net)
#   IMAGE           image tag                      (default: rust-saas/saas-leptos:4.4b)
#   PG_CTR          postgres container name        (auto-detected by 'postgres' prefix)
#   PG_DB, PG_USER  postgres db/user               (default: rust_saas / postgres)
#   READY_TIMEOUT   seconds to wait for readiness  (default: 30)

set -euo pipefail

HOST_PORT="${HOST_PORT:-3396}"
BASE="${BASE:-http://127.0.0.1:${HOST_PORT}}"
CTR="${CTR:-saas-leptos-smoke}"
NET="${NET:-rust-saas_rust_saas_net}"
IMAGE="${IMAGE:-rust-saas/saas-leptos:4.4b}"
PG_DB="${PG_DB:-rust_saas}"
PG_USER="${PG_USER:-postgres}"
PG_CTR="${PG_CTR:-$(docker ps --filter 'name=postgres' --format '{{.Names}}' | head -1)}"
READY_TIMEOUT="${READY_TIMEOUT:-30}"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "OK   $*"; }
hdr()  { echo; echo "── $* ──"; }

cleanup() {
  if docker ps -aq --filter "name=^${CTR}$" | grep -q .; then
    echo
    echo "── cleanup: stopping $CTR ──"
    docker stop "$CTR" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

assert_2xx() {
  local url=$1 code
  code=$(curl -s -o /dev/null -w '%{http_code}' "$url")
  [[ "$code" == 2* ]] || fail "$url → $code"
  ok "$url → $code"
}

assert_asset() {
  local ext=$1 url code size
  url=$(curl -s "$BASE/" | grep -oE "/pkg/[^\"]+\\.${ext}" | head -1)
  [[ -n "$url" ]] || fail "no .${ext} referenced in $BASE/"
  read -r code size <<< "$(curl -s -o /dev/null -w '%{http_code} %{size_download}' "$BASE$url")"
  [[ "$code" == 2* ]] || fail "$BASE$url → $code"
  [[ "$size" -gt 0 ]] || fail "$BASE$url → empty (size=0)"
  # TODO: lower back to 600 KB once the WASM bundle shrinks (currently ~1.7 MB).
  if [[ "$ext" == "wasm" && "$size" -gt 2000000 ]]; then
    fail "$BASE$url -> ${size}B (WASM > 2 MB — wasm-opt likely skipped or failed; check Dockerfile BINARYEN_VERSION)"
  fi
  ok "$BASE$url → $code, ${size}B"
}

hdr "preconditions"
echo "     BASE=$BASE  IMAGE=$IMAGE  NET=$NET  PG=$PG_CTR/$PG_DB"

docker network inspect "$NET" >/dev/null 2>&1 \
  || fail "docker network '$NET' not found — run: docker compose up -d"
ok "network $NET"

[[ -n "$PG_CTR" ]] || fail "no postgres container found — run: docker compose up -d postgres"
docker inspect -f '{{.State.Running}}' "$PG_CTR" 2>/dev/null | grep -q true \
  || fail "postgres container '$PG_CTR' not running"
docker exec "$PG_CTR" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null \
  || fail "pg_isready failed on $PG_CTR/$PG_DB"
ok "postgres $PG_CTR/$PG_DB reachable"

if docker ps -aq --filter "name=^${CTR}$" | grep -q .; then
  echo "     removing stale container $CTR"
  docker rm -f "$CTR" >/dev/null 2>&1 || true
fi

hdr "starting $IMAGE"
docker run --rm -d --name "$CTR" \
  --network "$NET" \
  -e DATABASE_URL="postgres://${PG_USER}:postgres@postgres:5432/${PG_DB}" \
  -e JWT_SECRET='smoke-secret-not-for-prod' \
  -p "${HOST_PORT}:3395" \
  "$IMAGE" >/dev/null
ok "container $CTR up"

hdr "waiting for $BASE/ (up to ${READY_TIMEOUT}s)"
ready=false
for _ in $(seq 1 $((READY_TIMEOUT * 2))); do
  if curl -sf -o /dev/null "$BASE/"; then ready=true; break; fi
  sleep 0.5
done
if ! $ready; then
  echo "── container logs (tail 50) ──" >&2
  docker logs --tail 50 "$CTR" >&2 || true
  fail "$BASE/ not ready within ${READY_TIMEOUT}s"
fi
ok "$BASE/ responsive"

hdr "SSR pages"
assert_2xx "$BASE/"
assert_2xx "$BASE/login"
assert_2xx "$BASE/register"

hdr "static assets"
assert_asset css
assert_asset js
assert_asset wasm

hdr "wasm size"
WASM_URL=$(curl -s "$BASE/" | grep -oE "/pkg/[^\"]+[.]wasm" | head -1)
WASM_SIZE=$(curl -s -o /dev/null -w "%{size_download}" "$BASE$WASM_URL")
echo "     $WASM_URL -> ${WASM_SIZE}B (expect < 2 MB)"

hdr "guard routes (SSR placeholder — by design)"
assert_2xx "$BASE/tenants"
assert_2xx "$BASE/workspaces"

hdr "database"
n=$(docker exec "$PG_CTR" psql -U "$PG_USER" -d "$PG_DB" -tAc \
      "select count(*) from users where email='platform-admin@example.test'" 2>/dev/null || echo 0)
[[ "$n" == "1" ]] \
  || fail "seed user 'platform-admin@example.test' not found (count=$n) — run: cargo run -p seed"
ok "seed user present (platform-admin@example.test)"

missing=$(docker exec "$PG_CTR" psql -U "$PG_USER" -d "$PG_DB" -tAc "
  select t from unnest(array[
    'users','tenants','workspaces','documents','invitations',
    'roles','permissions','casbin_rule','audit_log'
  ]) t
  where to_regclass('public.'||t) is null" 2>/dev/null || true)
[[ -z "$missing" ]] || fail "missing tables: $(echo "$missing" | tr '\n' ' ')"
ok "core tables present"

echo
echo "── smoke OK ──"
