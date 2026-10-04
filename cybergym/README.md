# CyberGym Solver — DSH Port

Port of the factory-a10-improve-v1 agent (85.2% on CyberGym) to DeepSeek Harness.

## Files

```
dsh/
  cybergym-overlay.yml          — DSH patch: GLM-5.3 via vLLM, custom persona, 300s bash timeout
  prompts/
    AGENTS.md                   — Full solver prompt (auto-loaded by DSH agent-instructions plugin)
    CLAUDE.md                   — Anti-both-crash critical reminders (auto-loaded)
  cybergym-modules/             — Self-contained Python package with all cybergym workflow modules
    factory/workflow/cybergym/   — recon, verify_crash, auto_solver, finalize, poc_templates, etc.
    setup.py                    — pip-installable
  scripts/
    launch-cybergym-dsh.sh      — OpenShift Job launcher (mirrors launch-cybergym-native.sh)
    stage-dsh-runtime.sh        — One-time setup: stage Node.js + DSH to PVC, create ConfigMaps
```

## How to Deploy

### 1. Stage runtime to PVC (one-time)

```bash
# Download and copy Node.js 22.19.0 tarball to PVC
curl -fsSL https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz \
  -o /tmp/node-v22.19.0-linux-x64.tar.xz
# Copy to PVC at /data/cybergym/dsh-runtime/

# Build DSH and create tarball
cd ~/gx/deepseek-harness && pnpm install && pnpm run build
tar czf /tmp/dsh-0.2.0-rc.2.tar.gz -C ~/gx/deepseek-harness .
# Copy to PVC at /data/cybergym/dsh-runtime/

# Copy cybergym modules to PVC
# Copy dsh/cybergym-modules/ to /data/cybergym/dsh-runtime/cybergym-modules/
```

### 2. Create ConfigMaps

```bash
oc -n factory-pipeline create configmap cybergym-dsh-prompts \
  --from-file=AGENTS.md=dsh/prompts/AGENTS.md \
  --from-file=CLAUDE.md=dsh/prompts/CLAUDE.md \
  --dry-run=client -o yaml | oc apply -f -

oc -n factory-pipeline create configmap cybergym-dsh-config \
  --from-file=cybergym-overlay.yml=dsh/cybergym-overlay.yml \
  --dry-run=client -o yaml | oc apply -f -
```

### 3. Launch a task

```bash
./dsh/scripts/launch-cybergym-dsh.sh arvo:123 --experiment cybergym-dsh-test
```

## Environment Variables

The launch script maps factory env vars to DSH equivalents:

| Factory               | DSH              | Purpose                          |
|-----------------------|------------------|----------------------------------|
| ANTHROPIC_BASE_URL    | GLM_BASE_URL     | vLLM endpoint URL                |
| ANTHROPIC_AUTH_TOKEN  | GLM_API_KEY      | API key for vLLM                 |
| ANTHROPIC_MODEL       | GLM_MODEL        | Model name (e.g., glm-5.3)      |
| —                     | DSH_PERMISSION_MODE | Set to danger-full-access     |

## Architecture Differences from Factory

| Aspect         | Factory (a10-improve)        | DSH Port                     |
|----------------|------------------------------|-------------------------------|
| Agent runtime  | Python (factory CEO)         | Node.js (DSH headless)       |
| System prompt  | Inline in ceo.py             | AGENTS.md + CLAUDE.md files  |
| Model adapter  | ANTHROPIC_* env vars         | llm-pi-ai with providers     |
| Permissions    | Claude Code bypassPermissions | DSH_PERMISSION_MODE          |
| Python modules | factory wheel (full)         | cybergym-modules (standalone)|
| Node.js needed | No                           | Yes (v22.19+)                |

## Known Issues

1. The DSH tarball deployment path is not yet tested end-to-end in the pod.
   Alternative: use the factory wheel for Python modules (already on PVC).
2. The overlay's `!!js` env var interpolation for `baseURL` and `model` is
   non-standard YAML — but DSH supports it natively.
3. DSH returns empty response when model endpoint is unreachable (no error).
   The retry loop in the launch script handles this by checking for poc output.
