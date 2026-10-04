#!/usr/bin/env bash
# Stage DSH runtime files to the PVC for pod use.
# Run this once before launching DSH-based CyberGym jobs.
#
# Stages:
#   1. Node.js binary tarball -> /data/cybergym/dsh-runtime/
#   2. DSH build artifact -> /data/cybergym/dsh-runtime/
#   3. Cybergym Python modules -> /data/cybergym/dsh-runtime/cybergym-modules/
#
# Also creates the ConfigMaps for DSH prompts and config.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DSH_DIR="$(dirname "$HERE")"

OC="${OC:-oc}"
NS="${NS:-factory-pipeline}"
NODE_VERSION="${NODE_VERSION:-22.19.0}"

echo "=== Staging DSH runtime to PVC ==="

# 1. Download Node.js if not cached locally
NODE_TAR="node-v${NODE_VERSION}-linux-x64.tar.xz"
if [ ! -f "/tmp/${NODE_TAR}" ]; then
    echo "Downloading Node.js ${NODE_VERSION}..."
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TAR}" -o "/tmp/${NODE_TAR}"
fi

# 2. Create a staging pod to copy files to PVC
echo "Creating staging pod..."
$OC -n "$NS" run dsh-stage --rm -i --restart=Never \
    --image=image-registry.openshift-image-registry.svc:5000/factory-pipeline/factory:ubuntu \
    --overrides='{
        "spec": {
            "containers": [{
                "name": "dsh-stage",
                "image": "image-registry.openshift-image-registry.svc:5000/factory-pipeline/factory:ubuntu",
                "command": ["bash", "-c", "mkdir -p /data/cybergym/dsh-runtime/cybergym-modules && echo READY && sleep 300"],
                "volumeMounts": [{"name": "data", "mountPath": "/data/cybergym", "subPath": "cybergym"}]
            }],
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "cybergym-data"}}]
        }
    }' -- bash -c "
        mkdir -p /data/cybergym/dsh-runtime
        echo 'Staging directory ready'
        sleep 300
    " &
STAGE_PID=$!

echo "Waiting for staging pod..."
sleep 10

# Copy Node.js tarball
echo "Copying Node.js tarball..."
$OC -n "$NS" cp "/tmp/${NODE_TAR}" dsh-stage:/data/cybergym/dsh-runtime/

# Copy cybergym modules
echo "Copying cybergym modules..."
$OC -n "$NS" cp "${DSH_DIR}/cybergym-modules/" dsh-stage:/data/cybergym/dsh-runtime/cybergym-modules/

# Clean up staging pod
$OC -n "$NS" delete pod dsh-stage --force 2>/dev/null || true
kill $STAGE_PID 2>/dev/null || true

# 3. Create ConfigMaps
echo "Creating ConfigMaps..."

# DSH prompts (AGENTS.md + CLAUDE.md)
$OC -n "$NS" create configmap cybergym-dsh-prompts \
    --from-file=AGENTS.md="${DSH_DIR}/prompts/AGENTS.md" \
    --from-file=CLAUDE.md="${DSH_DIR}/prompts/CLAUDE.md" \
    --dry-run=client -o yaml | $OC -n "$NS" apply -f -

# DSH config (overlay YAML)
$OC -n "$NS" create configmap cybergym-dsh-config \
    --from-file=cybergym-overlay.yml="${DSH_DIR}/cybergym-overlay.yml" \
    --dry-run=client -o yaml | $OC -n "$NS" apply -f -

echo "=== DSH runtime staged ==="
echo ""
echo "Next steps:"
echo "  1. Build and package DSH: cd ~/gx/deepseek-harness && pnpm run build && tar czf /tmp/dsh-0.2.0-rc.2.tar.gz ."
echo "  2. Copy DSH tarball to PVC: oc cp /tmp/dsh-0.2.0-rc.2.tar.gz dsh-stage:/data/cybergym/dsh-runtime/"
echo "  3. Launch a test task: ${DSH_DIR}/scripts/launch-cybergym-dsh.sh arvo:123 --experiment cybergym-dsh-test"
