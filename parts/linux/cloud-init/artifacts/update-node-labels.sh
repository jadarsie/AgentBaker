#!/usr/bin/env bash

# Updates Labels for this Kubernetes node (adds any missing, updates others to newest values, but never removes labels)

set -euo pipefail

NODE_NAME=$(echo $(hostname) | tr "[:upper:]" "[:lower:]")

echo "updating labels for ${NODE_NAME}"

KUBECONFIG=/var/lib/kubelet/kubeconfig
{{if IsControlPlane}}
KUBECONFIG=/etc/kubernetes/admin.conf
NODE_ROLE=",kubernetes.io/role=master"
{{else}}
NODE_ROLE=",kubernetes.io/role=agent"
{{end}}

FORMATTED_CURRENT_NODE_LABELS=$(kubectl label --kubeconfig ${KUBECONFIG} --list=true node $NODE_NAME | sort)

echo "current node labels (sorted): ${FORMATTED_CURRENT_NODE_LABELS}"

FORMATTED_NODE_LABELS_TO_UPDATE=$(echo ${KUBELET_NODE_LABELS}${NODE_ROLE} | tr ',' '\n' | sort)

echo "node labels to update (formatted+sorted): ${FORMATTED_NODE_LABELS_TO_UPDATE}"

MISSING_LABELS=$(comm -32 <(echo $FORMATTED_NODE_LABELS_TO_UPDATE | tr ' ' '\n') <(echo $FORMATTED_CURRENT_NODE_LABELS | tr ' ' '\n') | tr '\n' ' ')

echo "missing labels: ${MISSING_LABELS}"

if [ ! -z "$MISSING_LABELS" ]; then
  kubectl label --kubeconfig ${KUBECONFIG} --overwrite node $NODE_NAME $MISSING_LABELS
fi
#EOF
