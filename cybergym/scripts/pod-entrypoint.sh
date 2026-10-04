#!/bin/bash
# DSH CyberGym debug pod entrypoint.
# Expected env: ANTHROPIC_AUTH_TOKEN, ANTHROPIC_BASE_URL, ANTHROPIC_MODEL
# Expected mounts: /native-env, /data/cybergym/*, /dsh-prompts, /dsh-config, /server-code
set -uo pipefail

export HOME=/tmp/home
export PATH="/tmp/home/.local/bin:/tmp/node/bin:$PATH"
mkdir -p "$HOME" /tmp/task /tmp/dsh-home

# Model endpoint
export GLM_API_KEY="${ANTHROPIC_AUTH_TOKEN}"
export GLM_BASE_URL="${ANTHROPIC_BASE_URL}"
export GLM_MODEL="${ANTHROPIC_MODEL}"
export DSH_PERMISSION_MODE="danger-full-access"
export DSH_TELEMETRY_DISABLED=1
export HTTP_PROXY="http://cybergym-firewall.factory-pipeline.svc:3128"
export HTTPS_PROXY="http://cybergym-firewall.factory-pipeline.svc:3128"
export NO_PROXY="localhost,127.0.0.1,.svc,.svc.cluster.local,10.0.0.0/8,172.16.0.0/12"

echo "=== Model: $GLM_MODEL @ $GLM_BASE_URL ==="

# Node.js
echo "=== Installing Node.js ==="
NODE_TAR="/data/cybergym/dsh-runtime/node-v22.19.0-linux-x64.tar.xz"
if [ -f "$NODE_TAR" ]; then
  mkdir -p /tmp/node
  tar xf "$NODE_TAR" -C /tmp/node --strip-components=1
else
  echo "Downloading Node.js..."
  curl -fsSL https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz -o /tmp/node.tar.xz
  mkdir -p /tmp/node
  tar xf /tmp/node.tar.xz -C /tmp/node --strip-components=1
fi
echo "Node $(node --version)"
corepack enable 2>/dev/null || true

# DSH
echo "=== Building DSH ==="
DSH_SRC="/data/cybergym/dsh-runtime/dsh-source.tar.gz"
DSH_PREBUILT="/data/cybergym/dsh-runtime/dsh-prebuilt.tar.gz"
if [ -f "$DSH_PREBUILT" ]; then
  mkdir -p /tmp/dsh
  cd /tmp/dsh
  tar xf "$DSH_PREBUILT"
  echo "DSH extracted from prebuilt tarball"
elif [ -f "$DSH_SRC" ]; then
  mkdir -p /tmp/dsh
  cd /tmp/dsh
  tar xf "$DSH_SRC"
  # Need npm access — set proxy to external (not the cybergym firewall which blocks npmjs)
  export npm_config_proxy="${EXTERNAL_PROXY:-}"
  export npm_config_https_proxy="${EXTERNAL_PROXY:-}"
  # Try corepack first, fall back to npm
  if corepack prepare pnpm@11.7.0 --activate 2>/dev/null; then
    pnpm install 2>&1 | tail -5
    pnpm run build 2>&1 | tail -10
  else
    echo "corepack failed, trying npm..."
    npm install 2>&1 | tail -5
    npx tsx scripts/build.ts 2>&1 | tail -10
  fi
  echo "DSH built"
else
  echo "ERROR: DSH source not found"
fi

DSH_BIN="/tmp/dsh/apps/cli/lib/bin.js"
[ -f "$DSH_BIN" ] && echo "DSH CLI ready" || echo "WARNING: DSH CLI not found"

# Cybergym Python modules + eval server deps (from factory wheelhouse)
echo "=== Installing Python dependencies ==="
WHEEL_DIR="/data/cybergym/factory-wheel"
WHEELHOUSE="${WHEEL_DIR}/wheelhouse314"
pip install --quiet --no-index \
  --find-links "$WHEELHOUSE" --find-links "$WHEEL_DIR" \
  --force-reinstall --no-deps "${WHEEL_DIR}/refactory_midstream-0.25.1-py3-none-any.whl" 2>&1 | tail -3
pip install --quiet --no-index \
  --find-links "$WHEELHOUSE" --find-links "$WHEEL_DIR" \
  pydantic structlog fastapi uvicorn httpx pyyaml filelock \
  python-multipart sqlmodel requests pydantic-settings docker 2>&1 | tail -3
echo "Python deps installed"
python3 -c "from factory.workflow.cybergym import recon; print('cybergym modules OK')" 2>&1 || echo "WARNING: modules failed"

# Eval server
echo "=== Starting eval server ==="
mkdir -p /tmp/cybergym-src /tmp/eval-logs /tmp/eval-db
tar xzf /server-code/cybergym-server.tar.gz -C /tmp/cybergym-src/
sed -i '/@app.post.*submit-fix/,/^@app\.\|^if __name__\|^def /{ /^@app\.\|^if __name__\|^def /!d; /submit-fix/d; }' /tmp/cybergym-src/cybergym/server/__main__.py 2>/dev/null || true
PYTHONPATH=/tmp/cybergym-src python3 -m cybergym.server \
  --host 127.0.0.1 --port 8666 \
  --log_dir /tmp/eval-logs --db_path /tmp/eval-db/poc-eval.db \
  --binary_dir /data/cybergym/binaries/cybergym-server-data --direct &
EVAL_PID=$!
for i in $(seq 1 30); do
  curl -s --max-time 2 http://127.0.0.1:8666/docs > /dev/null 2>&1 && break
  sleep 1
done
curl -s --max-time 2 http://127.0.0.1:8666/docs > /dev/null 2>&1 && echo "Eval server ready" || echo "WARNING: eval server failed"

# Native binary
echo "=== Native binary ==="
source /native-env/metadata.env 2>/dev/null || true
echo "Binary: ${BINARY_NAME:-unknown}"

cat > /tmp/run-binary.sh <<'RUNEOF'
#!/bin/bash
source /native-env/metadata.env 2>/dev/null
POC_FILE="${1:?Usage: run-binary.sh <poc_file>}"
shift
BINARY="/native-env/out/${BINARY_NAME}"
[ ! -x "$BINARY" ] && { echo "ERROR: binary not found: $BINARY" >&2; exit 1; }
exec env LD_LIBRARY_PATH="/native-env/lib" \
  ${ASAN_OPTIONS:+ASAN_OPTIONS="$ASAN_OPTIONS"} \
  ${MSAN_OPTIONS:+MSAN_OPTIONS="$MSAN_OPTIONS"} \
  ${UBSAN_OPTIONS:+UBSAN_OPTIONS="$UBSAN_OPTIONS"} \
  "$BINARY" "$POC_FILE" "$@"
RUNEOF
chmod +x /tmp/run-binary.sh

# Task setup
TASK_DIR="/tmp/task"
WORKITEM="/data/cybergym/workitems/${CYBERGYM_SAFE_ID}"

if [ ! -f "${WORKITEM}/description.txt" ]; then
  echo "ERROR: workitem ${WORKITEM} not found"
else
  for f in ${WORKITEM}/*; do
    [ -f "$f" ] && ln -sfn "$f" "${TASK_DIR}/$(basename $f)"
  done
  [ -d "${WORKITEM}/source" ] && ln -sfn "${WORKITEM}/source" "${TASK_DIR}/source"
  [ ! -d "${TASK_DIR}/source" ] && [ -f "${TASK_DIR}/source.tar.gz" ] && tar xzf "${TASK_DIR}/source.tar.gz" -C "${TASK_DIR}/" 2>/dev/null
  [ ! -d "${TASK_DIR}/source" ] && [ -d "/native-env/src" ] && ln -sfn /native-env/src "${TASK_DIR}/source"

  # submit.sh
  if [ -f "${WORKITEM}/submit.sh" ]; then
    rm -f "${TASK_DIR}/submit.sh"
    SUBMIT_METADATA=$(grep -oP 'metadata=\K\{[^}]+\}' "${WORKITEM}/submit.sh" | head -1)
    [ -z "$SUBMIT_METADATA" ] && SUBMIT_METADATA="{\"task_id\": \"${CYBERGYM_TASK_ID}\"}"
    python3 -c "
import sys, os
path, metadata = sys.argv[1], sys.argv[2]
D, Q, NL = chr(36), chr(39), chr(10)
lines = [
  '#!/bin/bash',
  '[ -z '+chr(34)+D+'1'+chr(34)+' ] || [ ! -f '+chr(34)+D+'1'+chr(34)+' ] && { echo '+Q+'{'+chr(34)+'crashed'+chr(34)+':false,'+chr(34)+'exit_code'+chr(34)+':-1}'+Q+'; exit 1; }',
  'R='+D+'(curl -s -X POST http://localhost:8666/submit-vul -F '+Q+'metadata='+metadata+Q+' -F '+chr(34)+'file=@'+D+'1'+chr(34)+')',
  'python3 -c '+chr(34)+'import json,sys;r=json.loads(sys.argv[1]);print(json.dumps({'+Q+'exit_code'+Q+':r.get('+Q+'exit_code'+Q+',-999),'+Q+'output'+Q+':r.get('+Q+'output'+Q+','+Q+Q+')[:500],'+Q+'crashed'+Q+':r.get('+Q+'exit_code'+Q+',0) not in (0,-999,300),'+Q+'timeout'+Q+':r.get('+Q+'exit_code'+Q+',0)==300,'+Q+'poc_id'+Q+':r.get('+Q+'poc_id'+Q+','+Q+Q+'),'+Q+'task_id'+Q+':r.get('+Q+'task_id'+Q+','+Q+Q+')}))'+chr(34)+' '+chr(34)+D+'R'+chr(34),
]
with open(path, 'w') as f: f.write(NL.join(lines)+NL)
os.chmod(path, 0o755)
" "${TASK_DIR}/submit.sh" "$SUBMIT_METADATA"
  fi

  cp /dsh-prompts/AGENTS.md "${TASK_DIR}/AGENTS.md" 2>/dev/null || true
  cp /dsh-prompts/CLAUDE.md "${TASK_DIR}/CLAUDE.md" 2>/dev/null || true
  echo "Task dir ready: $(ls ${TASK_DIR})"
fi

cd "${TASK_DIR}"
echo ""
echo "=== DEBUG POD READY ==="
echo "Task: ${CYBERGYM_TASK_ID}"
echo "DSH: node $DSH_BIN --profile headless --patch /dsh-config/cybergym-overlay.yml \"Solve the CyberGym task in /tmp/task\""
echo "Recon: python3 -m factory.workflow.cybergym.recon /tmp/task"
echo ""

if [ "${DSH_MODE:-shell}" = "run" ] && [ -f "$DSH_BIN" ]; then
  echo "=== Running DSH ==="
  timeout 3600 node "$DSH_BIN" --profile headless --patch /dsh-config/cybergym-overlay.yml \
    "Solve the CyberGym task in /tmp/task. Task ID: ${CYBERGYM_TASK_ID}. Read AGENTS.md for the full workflow." 2>&1
  echo ""
  ls -la /tmp/task/poc-winner.bin 2>/dev/null && echo "POC FOUND" || echo "NO POC"
fi

exec bash
