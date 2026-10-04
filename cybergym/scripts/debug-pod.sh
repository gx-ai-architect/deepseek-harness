#!/usr/bin/env bash
# Launch an interactive debug pod for testing DSH CyberGym agent.
# Usage:
#   ./debug-pod.sh arvo:10306             # run DSH agent
#   ./debug-pod.sh arvo:10306 --shell     # just drop into bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export HTTPS_PROXY="${HTTPS_PROXY:-http://10.2.32.57:3128}"
export HTTP_PROXY="${HTTP_PROXY:-http://10.2.32.57:3128}"

OC="${OC:-oc}"
NS="${NS:-factory-pipeline}"
IMAGE="${IMAGE:-image-registry.openshift-image-registry.svc:5000/factory-pipeline/factory:ubuntu}"
MEMORY="${MEMORY:-8Gi}"
DSH_MODE="run"

TASK_ID=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --shell) DSH_MODE="shell"; shift ;;
        --memory) MEMORY="$2"; shift 2 ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *) TASK_ID="$1"; shift ;;
    esac
done

[ -z "$TASK_ID" ] && { echo "Usage: $0 <task_id> [--shell]"; exit 1; }

SAFE_ID="${TASK_ID//[:\/]/_}"
SUBSET="${TASK_ID%%:*}"
SUBID="${TASK_ID#*:}"
POD_NAME="dsh-debug-${SAFE_ID}"
POD_NAME=$(echo "$POD_NAME" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | head -c 63 | sed 's/-*$//')

if [ "$SUBSET" = "arvo" ]; then
    VUL_IMAGE="n132/arvo:${SUBID}-vul"
elif [ "$SUBSET" = "oss-fuzz" ]; then
    VUL_IMAGE="cybergym/oss-fuzz:${SUBID}-vul"
else
    echo "ERROR: Unknown subset: $SUBSET" >&2; exit 1
fi

echo "Task: $TASK_ID  Image: $VUL_IMAGE  Pod: $POD_NAME  Mode: $DSH_MODE"

# Ensure the entrypoint ConfigMap exists
$OC -n "$NS" create configmap cybergym-dsh-entrypoint \
  --from-file=entrypoint.sh="${HERE}/pod-entrypoint.sh" \
  --dry-run=client -o yaml | $OC -n "$NS" apply -f -

# Delete old pod if exists
$OC -n "$NS" delete pod "$POD_NAME" --ignore-not-found 2>/dev/null || true
sleep 2

$OC -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  namespace: ${NS}
  labels:
    app: dsh-debug
    cybergym/task-id: "${SAFE_ID}"
spec:
  serviceAccountName: pipeline
  restartPolicy: Never
  activeDeadlineSeconds: 14400
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/hostname
            operator: In
            values:
            - rits-roce-z6lst-new-worker-1-0000
            - rits-roce-z6lst-new-worker-1-0001
            - rits-roce-z6lst-new-worker-1-0002
            - rits-roce-z6lst-new-worker-1-0003
            - rits-roce-z6lst-new-worker-2-0000
            - rits-roce-z6lst-new-worker-2-0001
            - rits-roce-z6lst-new-worker-2-0002
            - rits-roce-z6lst-new-worker-2-0003
            - rits-roce-z6lst-new-worker-3-0000
            - rits-roce-z6lst-new-worker-3-0001
            - rits-roce-z6lst-new-worker-3-0002
            - rits-roce-z6lst-new-worker-3-0003
            - rits-roce-z6lst-llmd-router-1-4p6ls
            - rits-roce-z6lst-llmd-router-2-jtghw
            - rits-roce-z6lst-llmd-router-3-c5f65
  initContainers:
  - name: extract-env
    image: ${VUL_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      mkdir -p /extract/out /extract/lib /extract/src /extract/bin
      cp /bin/arvo /extract/bin/arvo 2>/dev/null || true
      cp /usr/local/bin/run_poc /extract/bin/run_poc 2>/dev/null || true
      cp -a /out/* /extract/out/ 2>/dev/null || true
      for bin in /extract/out/*; do
        [ -x "\$bin" ] || continue
        ldd "\$bin" 2>/dev/null | grep -oP '=> \K/[^ ]+' | while read lib; do
          cp -n "\$lib" /extract/lib/ 2>/dev/null || true
        done
      done
      cp /lib64/ld-linux-x86-64.so.2 /extract/lib/ 2>/dev/null || true
      cp /lib/x86_64-linux-gnu/ld-*.so* /extract/lib/ 2>/dev/null || true
      cp /lib/x86_64-linux-gnu/libc.so* /extract/lib/ 2>/dev/null || true
      cp /lib/x86_64-linux-gnu/libm.so* /extract/lib/ 2>/dev/null || true
      cp /lib/x86_64-linux-gnu/libpthread.so* /extract/lib/ 2>/dev/null || true
      cp /lib/x86_64-linux-gnu/libdl.so* /extract/lib/ 2>/dev/null || true
      cp /lib/x86_64-linux-gnu/librt.so* /extract/lib/ 2>/dev/null || true
      cp /lib/x86_64-linux-gnu/libstdc++.so* /extract/lib/ 2>/dev/null || true
      cp /usr/lib/x86_64-linux-gnu/libstdc++.so* /extract/lib/ 2>/dev/null || true
      cp -a /src/* /extract/src/ 2>/dev/null || true
      BINARY_NAME=""
      if [ -f /bin/arvo ]; then
        BINARY_NAME=\$(grep -oP '/out/\K[^ ]+' /bin/arvo | head -1)
      fi
      if [ -z "\$BINARY_NAME" ] && [ -f /usr/local/bin/run_poc ]; then
        BINARY_NAME=\$(ls -S /extract/out/ | while read f; do
          case "\$f" in llvm-*|*.dict|*.options|*.zip|*.txt) continue;; esac
          [ -x "/extract/out/\$f" ] && echo "\$f" && break
        done)
      fi
      [ -z "\$BINARY_NAME" ] && BINARY_NAME=\$(ls /extract/out/ | grep -v '\\.\\|^lib\\|^llvm' | head -1)
      echo "BINARY_NAME=\${BINARY_NAME}" > /extract/metadata.env
      echo "VUL_IMAGE=${VUL_IMAGE}" >> /extract/metadata.env
      grep -E '^export (ASAN|MSAN|UBSAN|FUZZER|SANITIZER|FUZZING)' /bin/arvo >> /extract/metadata.env 2>/dev/null || true
      grep -E '^export (ASAN|MSAN|UBSAN|FUZZER|SANITIZER|FUZZING)' /usr/local/bin/run_poc >> /extract/metadata.env 2>/dev/null || true
      echo "Extracted: \${BINARY_NAME}"
    volumeMounts:
    - name: native-env
      mountPath: /extract
    resources:
      requests:
        cpu: "100m"
        memory: 512Mi
      limits:
        cpu: "1"
        memory: 4Gi
  containers:
  - name: debug
    image: ${IMAGE}
    imagePullPolicy: IfNotPresent
    stdin: true
    tty: true
    command: ["/bin/bash", "/entrypoint/entrypoint.sh"]
    env:
    - name: CYBERGYM_TASK_ID
      value: "${TASK_ID}"
    - name: CYBERGYM_SAFE_ID
      value: "${SAFE_ID}"
    - name: DSH_MODE
      value: "${DSH_MODE}"
    - name: ANTHROPIC_BASE_URL
      valueFrom:
        configMapKeyRef:
          name: model-endpoint
          key: ANTHROPIC_BASE_URL
    - name: ANTHROPIC_MODEL
      valueFrom:
        configMapKeyRef:
          name: model-endpoint
          key: ANTHROPIC_MODEL
    - name: ANTHROPIC_AUTH_TOKEN
      valueFrom:
        secretKeyRef:
          name: model-endpoint-auth
          key: ANTHROPIC_AUTH_TOKEN
          optional: true
    resources:
      requests:
        cpu: "250m"
        memory: 2Gi
      limits:
        cpu: "2"
        memory: "${MEMORY}"
    volumeMounts:
    - name: native-env
      mountPath: /native-env
      readOnly: true
    - name: data
      mountPath: /data/cybergym/workitems/${SAFE_ID}
      subPath: cybergym/workitems/${SAFE_ID}
      readOnly: true
    - name: data
      mountPath: /data/cybergym/binaries/cybergym-server-data/${SUBSET}/${SUBID}/vul
      subPath: cybergym/binaries/cybergym-server-data/${SUBSET}/${SUBID}/vul
      readOnly: true
    - name: data
      mountPath: /data/cybergym/factory-wheel
      subPath: cybergym/factory-wheel
      readOnly: true
    - name: data
      mountPath: /data/cybergym/dsh-runtime
      subPath: cybergym/dsh-runtime
      readOnly: true
    - name: server-code
      mountPath: /server-code
      readOnly: true
    - name: dsh-prompts
      mountPath: /dsh-prompts
      readOnly: true
    - name: dsh-config
      mountPath: /dsh-config
      readOnly: true
    - name: entrypoint
      mountPath: /entrypoint
      readOnly: true
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: native-env
    emptyDir:
      sizeLimit: 10Gi
  - name: data
    persistentVolumeClaim:
      claimName: cybergym-data
  - name: server-code
    configMap:
      name: cybergym-server-code
  - name: dsh-prompts
    configMap:
      name: cybergym-dsh-prompts
  - name: dsh-config
    configMap:
      name: cybergym-dsh-config
  - name: entrypoint
    configMap:
      name: cybergym-dsh-entrypoint
      defaultMode: 0755
  - name: tmp
    emptyDir:
      sizeLimit: 30Gi
EOF

echo ""
echo "Pod $POD_NAME creating. To watch:"
echo "  oc -n $NS logs -f $POD_NAME"
echo "  oc -n $NS rsh $POD_NAME"
echo "  oc -n $NS delete pod $POD_NAME"
