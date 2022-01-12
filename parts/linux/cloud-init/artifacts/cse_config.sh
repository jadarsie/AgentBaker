#!/bin/bash
NODE_INDEX=$(hostname | tail -c 2)
NODE_NAME=$(hostname)

configureAdminUser(){
    chage -E -1 -I -1 -m 0 -M 99999 "${ADMINUSER}"
    chage -l "${ADMINUSER}"
}

RefreshEtcdManifest() {
    # If initial-cluster does not contains all 3 ETCD cluster
    # Wait for the ETCD started on all nodes and update the ETCD configration by re-join the node to the cluster

    extractEtcdctl || exit $ERR_ASH_KUBEADM_REFRESH_ETCD_MANIFEST

    ETCD_INITIAL_CLUSTER_STRING=$(grep -E "initial-cluster=" /etc/kubernetes/manifests/etcd.yaml | grep -oE "aks-master.*")
    echo "ETCD_INITIAL_CLUSTER_STRING $ETCD_INITIAL_CLUSTER_STRING"
    IFS=',' read -a ETCD_INITIAL_CLUSTER_STRING_ARRAY <<< $ETCD_INITIAL_CLUSTER_STRING
    echo "ETCD_INITIAL_CLUSTER_STRING_ARRAY Count ${#ETCD_INITIAL_CLUSTER_STRING_ARRAY[@]}"

    if [ 3 !=  ${#ETCD_INITIAL_CLUSTER_STRING_ARRAY[@]} ]; then
                ARE_ETCD_MEMBERS_READY=false
                for i in {1..30}
                do
                        ETCDCTL_API=3
                        ETCD_MEMBER_COUNT=$(retrycmd_if_failure_no_stats 10 15 300 etcdctl member list --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key | grep -c "started, aks-master")
                        if [ $ETCD_MEMBER_COUNT == 3 ]
                        then
                                ARE_ETCD_MEMBERS_READY=true
                                break
                        fi
                        sleep 30
                done
                retrycmd_if_failure_no_stats 10 15 300 etcdctl member list --cacert /etc/kubernetes/pki/etcd/ca.crt --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key
                echo "ARE_ETCD_MEMBERS_READY $ARE_ETCD_MEMBERS_READY"
                if [ "$ARE_ETCD_MEMBERS_READY" == "true" ] ; then
                        echo "All ETCD members are ready"
                        retrycmd_if_failure_no_stats 10 15 300 kubeadm join phase control-plane-join etcd --config ${CONFIG} -v 9 || exit $ERR_ASH_KUBEADM_REFRESH_ETCD_MANIFEST
                        echo "etcd manifest update is completed"
                else
                        echo "Some ETCD members are not ready"
                        exit $ERR_ASH_KUBEADM_REFRESH_ETCD_MANIFEST
                fi
    else
        echo "ETCD_INITIAL_CLUSTER_STRING contains 3 members, skipping etcd manifest update"
    fi
}

customizeK8s() {
    wait_for_file 1200 1 /etc/kubernetes/kubeadm-config.yaml || exit $ERR_FILE_WATCH_TIMEOUT
    wait_for_file 1200 1 /etc/kubernetes/addons/kube-proxy.yaml || exit $ERR_FILE_WATCH_TIMEOUT
    wait_for_file 1200 1 /etc/kubernetes/addons/coredns.yaml || exit $ERR_FILE_WATCH_TIMEOUT

    mkdir -p /etc/kubernetes/pki/etcd
    cp -p /etc/kubernetes/certs/ca.crt /etc/kubernetes/pki/ca.crt
    cp -p /etc/kubernetes/pki/sa.key /etc/kubernetes/pki/sa.pub
    cp -p /etc/kubernetes/pki/ca.crt /etc/kubernetes/pki/front-proxy-ca.crt
    cp -p /etc/kubernetes/pki/ca.key /etc/kubernetes/pki/front-proxy-ca.key
    cp -p /etc/kubernetes/pki/ca.crt /etc/kubernetes/pki/etcd/ca.crt
    cp -p /etc/kubernetes/pki/ca.key /etc/kubernetes/pki/etcd/ca.key

    kubeletserver_key="/etc/kubernetes/certs/kubeletserver.key"
    kubeletserver_crt="/etc/kubernetes/certs/kubeletserver.crt"
    openssl genrsa -out $kubeletserver_key 2048
    openssl req -new -x509 -days 7300 -key $kubeletserver_key -out $kubeletserver_crt -subj "/CN=$(hostname)"

    mkdir -p /etc/kubernetes/patches
    KubeControllerManagerPatch

    FIRST_MASTER_NODE=true
    echo $NODE_NAME | grep -E '*-0$' > /dev/null
    if [[ "$?" != "0" ]]; then
        FIRST_MASTER_NODE=false
    fi
    if [[ -d /var/lib/etcddisk/etcd/member/ ]]; then
        FIRST_MASTER_NODE=false
    fi  

    if [ "${FIRST_MASTER_NODE}" = true ]; then
        local ADDON_CONFIG=$(mktemp)
        OLD="controlPlaneEndpoint: ${API_SERVER_NAME}"
        NEW="controlPlaneEndpoint: ${INTERNAL_LB_IP}"
        sed "s/${OLD}/${NEW}/1" ${CONFIG} > ${ADDON_CONFIG}

        retrycmd_if_failure_no_stats 10 15 180 kubeadm init phase certs all --config ${CONFIG} -v 9 || exit $ERR_ASH_KUBEADM_GEN_FILES
        retrycmd_if_failure_no_stats 10 15 180 kubeadm init phase kubeconfig all --config ${CONFIG} -v 9 || exit $ERR_ASH_KUBEADM_GEN_FILES
        retrycmd_if_failure_no_stats 10 15 180 kubeadm init phase control-plane all --config ${CONFIG} --experimental-patches /etc/kubernetes/patches -v 9 || exit $ERR_ASH_KUBEADM_GEN_FILES
        retrycmd_if_failure_no_stats 10 15 300 kubeadm init --config ${CONFIG} --skip-phases=certs,kubeconfig,control-plane,addon --ignore-preflight-errors=all -v 9 || exit $ERR_ASH_KUBEADM_INIT_JOIN

        # TODO Remove line below once /etc/kubernetes/addons/psp.yaml is baked
        PodSecurityPolicies
        retrycmd_if_failure_no_stats 10 15 10 kubectl apply -f /etc/kubernetes/addons/psp.yaml --kubeconfig ${KUBECONFIG} || exit $ERR_ASH_APPLY_ADDON

        retrycmd_if_failure_no_stats 10 15 180 kubectl create clusterrolebinding nodegroup --clusterrole system:node --group system:nodes --kubeconfig ${KUBECONFIG}
        retrycmd_if_failure_no_stats 10 15 180 kubectl create clusterrolebinding node-kubeproxy --clusterrole system:node-proxier --group system:nodes --kubeconfig ${KUBECONFIG}

        retrycmd_if_failure_no_stats 10 15 10 kubectl apply -f /etc/kubernetes/addons/kube-proxy.yaml --kubeconfig ${KUBECONFIG} || exit $ERR_ASH_APPLY_ADDON
        retrycmd_if_failure_no_stats 10 15 10 kubectl apply -f /etc/kubernetes/addons/coredns.yaml --kubeconfig ${KUBECONFIG} || exit $ERR_ASH_APPLY_ADDON
    
        for ADDON in {{GetAddonsURI}}; do
            retrycmd_if_failure_no_stats 10 15 180 kubectl apply -f ${ADDON} --kubeconfig ${KUBECONFIG} || exit $ERR_ASH_APPLY_ADDON
        done
    else
        retrycmd_if_failure_no_stats 10 15 180 kubeadm join phase control-plane-prepare certs --config ${CONFIG} -v 9 || exit $ERR_ASH_KUBEADM_GEN_FILES
        retrycmd_if_failure_no_stats 10 15 180 kubeadm join phase control-plane-prepare kubeconfig --config ${CONFIG} -v 9 || exit $ERR_ASH_KUBEADM_GEN_FILES

        retrycmd_if_failure_no_stats 10 15 180 kubectl get cm kubeadm-config -n kube-system -o yaml --kubeconfig ${KUBECONFIG} > /tmp/kubeadm-config.yaml || exit $ERR_ASH_KUBEADM_GEN_FILES
        sed "s/v1.[0-9]*.[0-9]*-azs$/v{{KubernetesVersion}}-azs/1" /tmp/kubeadm-config.yaml > /tmp/kubeadm-upgrade.yaml
        cmp -s /tmp/kubeadm-config.yaml /tmp/kubeadm-upgrade.yaml
        UPGRADE=$?

        if [ $UPGRADE == 1 ] ; then
            CUR_MINOR=$(grep -oh "v1.[0-9]*.[0-9]*-azs$" /tmp/kubeadm-config.yaml | grep -oh "\.[0-9][0-9]\." | grep -o [0-9][0-9])
            NEW_MINOR=$(echo {{KubernetesVersion}} | grep -oh "\.[0-9][0-9]\." | grep -o [0-9][0-9])

            echo "upgrading control plane node to kubernetes v{{KubernetesVersion}}"
            kubectl create role kubeadm:kubelet-config-1.${NEW_MINOR} -n kube-system --verb=get --resource=configmaps --resource-name=kubelet-config-1.${NEW_MINOR} --dry-run=client -o yaml \
            | retrycmd_if_failure_no_stats 10 15 30 kubectl apply --kubeconfig ${KUBECONFIG} -f - || exit $ERR_ASH_KUBEADM_INIT_JOIN
            
            kubectl create rolebinding kubeadm:kubelet-config-1.${NEW_MINOR} -n kube-system --role=kubeadm:kubelet-config-1.${NEW_MINOR} --group=system:nodes --group=system:bootstrappers:kubeadm:default-node-token --dry-run=client -o yaml \
            | retrycmd_if_failure_no_stats 10 15 30 kubectl apply --kubeconfig ${KUBECONFIG} -f - || exit $ERR_ASH_KUBEADM_INIT_JOIN

            kubectl create clusterrole kubeadm:get-nodes --verb=get --resource=nodes --dry-run=client -o yaml \
            | retrycmd_if_failure_no_stats 10 15 30 kubectl apply --kubeconfig ${KUBECONFIG} -f - || exit $ERR_ASH_KUBEADM_INIT_JOIN

            kubectl create clusterrolebinding kubeadm:get-nodes --clusterrole=kubeadm:get-nodes --group=system:bootstrappers:kubeadm:default-node-token --dry-run=client -o yaml \
            | retrycmd_if_failure_no_stats 10 15 30 kubectl apply --kubeconfig ${KUBECONFIG} -f - || exit $ERR_ASH_KUBEADM_INIT_JOIN

            retrycmd_if_failure_no_stats 10 15 30 kubectl get cm kubelet-config-1.${CUR_MINOR} -n kube-system -o yaml --kubeconfig ${KUBECONFIG} > kubelet-config.yaml || exit $ERR_ASH_KUBEADM_INIT_JOIN

            sed "/resourceVersion/d" kubelet-config.yaml | sed "s/kubelet-config-1.${CUR_MINOR}/kubelet-config-1.${NEW_MINOR}/1" \
            | retrycmd_if_failure_no_stats 10 15 30 kubectl apply --kubeconfig ${KUBECONFIG} -f - || exit $ERR_ASH_KUBEADM_INIT_JOIN

            retrycmd_if_failure_no_stats 10 15 30 kubectl replace -n kube-system cm kubeadm-conf -f /tmp/kubeadm-upgrade.yaml --kubeconfig ${KUBECONFIG} || exit $ERR_ASH_KUBEADM_INIT_JOIN

            retrycmd_if_failure_no_stats 10 15 30 kubectl apply -f /etc/kubernetes/addons/coredns.yaml --kubeconfig ${KUBECONFIG} || exit $ERR_ASH_APPLY_ADDON
        fi

        retrycmd_if_failure_no_stats 10 15 180 kubeadm join phase control-plane-prepare control-plane --config ${CONFIG} --experimental-patches /etc/kubernetes/patches -v 9 || exit $ERR_ASH_KUBEADM_GEN_FILES
        retrycmd_if_failure_no_stats 10 15 180 kubeadm join phase kubelet-start --config ${CONFIG} -v 9 || exit $ERR_KUBELET_START_FAIL
        retrycmd_if_failure_no_stats 10 15 300 kubeadm join phase control-plane-join all --config ${CONFIG} -v 9 || exit $ERR_ASH_KUBEADM_INIT_JOIN
        retrycmd_if_failure_no_stats 10 15 180 kubectl uncordon ${NODE_NAME} --kubeconfig ${KUBECONFIG} || exit $ERR_ASH_KUBEADM_INIT_JOIN
    fi

    RefreshEtcdManifest || exit $ERR_ASH_KUBEADM_REFRESH_ETCD_MANIFEST
}

KubeControllerManagerPatch() {
    cat << EOF > /etc/kubernetes/patches/kube-controller-manager+strategic.yaml
spec:
  containers:
  - name: kube-controller-manager
    env:
    - name: AZURE_ENVIRONMENT_FILEPATH
      value: /etc/kubernetes/azurestackcloud.json
EOF
}

# TODO Remove function once /etc/kubernetes/addons/psp.yaml is baked
PodSecurityPolicies() {
    if [ ! -f /etc/kubernetes/addons/psp.yaml ]; then
    cat << EOF > /etc/kubernetes/addons/psp.yaml
# source: https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/policy/privileged-psp.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
---
# source: https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/policy/restricted-psp.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName:  'runtime/default'
spec:
  privileged: false
  # Required to prevent escalations to root.
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  # Allow core volume types.
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    # Assume that ephemeral CSI drivers & persistentVolumes set up by the cluster admin are safe to use.
    - 'csi'
    - 'persistentVolumeClaim'
    - 'ephemeral'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    # Require the container to run without root privileges.
    rule: 'MustRunAsNonRoot'
  seLinux:
    # This policy assumes the nodes are using AppArmor rather than SELinux.
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  readOnlyRootFilesystem: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp:privileged
rules:
- apiGroups: ['extensions']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - privileged
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp:restricted
rules:
- apiGroups: ['extensions']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - restricted
---
# authenticated users use psp:privileged cluster wide
# cluster admin should replace this cluster role binding to tight access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: authenticated:privileged
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: psp:privileged
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
---
# cluster-admins and kube-system service accounts use psp:privileged
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: control-plane:privileged
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: psp:privileged
subjects:
- kind: Group
  name: system:masters
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: system:serviceaccounts:kube-system
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: system:nodes
  apiGroup: rbac.authorization.k8s.io
EOF
    fi
}

{{- if EnableHostsConfigAgent}}
configPrivateClusterHosts() {
  systemctlEnableAndStart reconcile-private-hosts || exit $ERR_SYSTEMCTL_START_FAIL
}
{{- end}}

ensureRPC() {
    systemctlEnableAndStart rpcbind || exit $ERR_SYSTEMCTL_START_FAIL
    systemctlEnableAndStart rpc-statd || exit $ERR_SYSTEMCTL_START_FAIL
}

{{- if ShouldConfigTransparentHugePage}}
configureTransparentHugePage() {
    ETC_SYSFS_CONF="/etc/sysfs.conf"
    THP_ENABLED={{GetTransparentHugePageEnabled}}
    if [[ "${THP_ENABLED}" != "" ]]; then
        echo "${THP_ENABLED}" > /sys/kernel/mm/transparent_hugepage/enabled
        echo "kernel/mm/transparent_hugepage/enabled=${THP_ENABLED}" >> ${ETC_SYSFS_CONF}
    fi
    THP_DEFRAG={{GetTransparentHugePageDefrag}}
    if [[ "${THP_DEFRAG}" != "" ]]; then
        echo "${THP_DEFRAG}" > /sys/kernel/mm/transparent_hugepage/defrag
        echo "kernel/mm/transparent_hugepage/defrag=${THP_DEFRAG}" >> ${ETC_SYSFS_CONF}
    fi
}
{{- end}}

{{- if ShouldConfigSwapFile}}
configureSwapFile() {
    SWAP_SIZE_KB=$(expr {{GetSwapFileSizeMB}} \* 1000)
    DISK_FREE_KB=$(df /dev/sdb1 | sed 1d | awk '{print $4}')
    if [[ ${DISK_FREE_KB} -gt ${SWAP_SIZE_KB} ]]; then
        SWAP_LOCATION=/mnt/swapfile
        retrycmd_if_failure 24 5 25 fallocate -l ${SWAP_SIZE_KB}K ${SWAP_LOCATION} || exit $ERR_SWAP_CREAT_FAIL
        chmod 600 ${SWAP_LOCATION}
        retrycmd_if_failure 24 5 25 mkswap ${SWAP_LOCATION} || exit $ERR_SWAP_CREAT_FAIL
        retrycmd_if_failure 24 5 25 swapon ${SWAP_LOCATION} || exit $ERR_SWAP_CREAT_FAIL
        retrycmd_if_failure 24 5 25 swapon --show | grep ${SWAP_LOCATION} || exit $ERR_SWAP_CREAT_FAIL
        echo "${SWAP_LOCATION} none swap sw 0 0" >> /etc/fstab
    else
        echo "Insufficient disk space creating swap file: request ${SWAP_SIZE_KB} free ${DISK_FREE_KB}"
        exit $ERR_SWAP_CREAT_INSUFFICIENT_DISK_SPACE
    fi
}
{{- end}}

{{- if ShouldConfigureHTTPProxy}}
configureEtcEnvironment() {
    {{- if HasHTTPProxy }}
    echo 'HTTP_PROXY="{{GetHTTPProxy}}"' >> /etc/environment
    echo 'http_proxy="{{GetHTTPProxy}}"' >> /etc/environment
    {{- end}}
    {{- if HasHTTPSProxy }}
    echo 'HTTPS_PROXY="{{GetHTTPSProxy}}"' >> /etc/environment
    echo 'https_proxy="{{GetHTTPSProxy}}"' >> /etc/environment
    {{- end}}
    {{- if HasNoProxy }}
    echo 'NO_PROXY="{{GetNoProxy}}"' >> /etc/environment
    echo 'no_proxy="{{GetNoProxy}}"' >> /etc/environment
    {{- end}}
}
{{- end}}

{{- if ShouldConfigureHTTPProxyCA}}
configureHTTPProxyCA() {
    openssl x509 -outform pem -in /usr/local/share/ca-certificates/proxyCA.pem -out /usr/local/share/ca-certificates/proxyCA.crt || exit $ERR_HTTP_PROXY_CA_CONVERT
    rm -f /usr/local/share/ca-certificates/proxyCA.pem
    update-ca-certificates || exit $ERR_HTTP_PROXY_CA_UPDATE
}
{{- end}}

configureKubeletServerCert() {
    KUBELET_SERVER_PRIVATE_KEY_PATH="/etc/kubernetes/certs/kubeletserver.key"
    KUBELET_SERVER_CERT_PATH="/etc/kubernetes/certs/kubeletserver.crt"

    openssl genrsa -out $KUBELET_SERVER_PRIVATE_KEY_PATH 2048
    openssl req -new -x509 -days 7300 -key $KUBELET_SERVER_PRIVATE_KEY_PATH -out $KUBELET_SERVER_CERT_PATH -subj "/CN=${NODE_NAME}"
}

configureK8s() {
    KUBELET_PRIVATE_KEY_PATH="/etc/kubernetes/certs/client.key"
    touch "${KUBELET_PRIVATE_KEY_PATH}"
    chmod 0600 "${KUBELET_PRIVATE_KEY_PATH}"
    chown root:root "${KUBELET_PRIVATE_KEY_PATH}"

    APISERVER_PUBLIC_KEY_PATH="/etc/kubernetes/certs/apiserver.crt"
    touch "${APISERVER_PUBLIC_KEY_PATH}"
    chmod 0644 "${APISERVER_PUBLIC_KEY_PATH}"
    chown root:root "${APISERVER_PUBLIC_KEY_PATH}"

    AZURE_JSON_PATH="/etc/kubernetes/azure.json"
    touch "${AZURE_JSON_PATH}"
    chmod 0600 "${AZURE_JSON_PATH}"
    chown root:root "${AZURE_JSON_PATH}"

    set +x
    echo "${KUBELET_PRIVATE_KEY}" | base64 --decode > "${KUBELET_PRIVATE_KEY_PATH}"
    echo "${APISERVER_PUBLIC_KEY}" | base64 --decode > "${APISERVER_PUBLIC_KEY_PATH}"
    {{/* Perform the required JSON escaping */}}
    SERVICE_PRINCIPAL_CLIENT_SECRET=${SERVICE_PRINCIPAL_CLIENT_SECRET//\\/\\\\}
    SERVICE_PRINCIPAL_CLIENT_SECRET=${SERVICE_PRINCIPAL_CLIENT_SECRET//\"/\\\"}
    cat << EOF > "${AZURE_JSON_PATH}"
{
    {{- if IsAKSCustomCloud}}
    "cloud": "AzureStackCloud",
    {{- else}}
    "cloud": "{{GetTargetEnvironment}}",
    {{- end}}
    "tenantId": "${TENANT_ID}",
    "subscriptionId": "${SUBSCRIPTION_ID}",
    "aadClientId": "${SERVICE_PRINCIPAL_CLIENT_ID}",
    "aadClientSecret": "${SERVICE_PRINCIPAL_CLIENT_SECRET}",
    "resourceGroup": "${RESOURCE_GROUP}",
    "location": "${LOCATION}",
    "vmType": "${VM_TYPE}",
    "subnetName": "${SUBNET}",
    "securityGroupName": "${NETWORK_SECURITY_GROUP}",
    "vnetName": "${VIRTUAL_NETWORK}",
    "vnetResourceGroup": "${VIRTUAL_NETWORK_RESOURCE_GROUP}",
    "routeTableName": "${ROUTE_TABLE}",
    "primaryAvailabilitySetName": "${PRIMARY_AVAILABILITY_SET}",
    "primaryScaleSetName": "${PRIMARY_SCALE_SET}",
    "cloudProviderBackoffMode": "${CLOUDPROVIDER_BACKOFF_MODE}",
    "cloudProviderBackoff": ${CLOUDPROVIDER_BACKOFF},
    "cloudProviderBackoffRetries": ${CLOUDPROVIDER_BACKOFF_RETRIES},
    "cloudProviderBackoffExponent": ${CLOUDPROVIDER_BACKOFF_EXPONENT},
    "cloudProviderBackoffDuration": ${CLOUDPROVIDER_BACKOFF_DURATION},
    "cloudProviderBackoffJitter": ${CLOUDPROVIDER_BACKOFF_JITTER},
    "cloudProviderRateLimit": ${CLOUDPROVIDER_RATELIMIT},
    "cloudProviderRateLimitQPS": ${CLOUDPROVIDER_RATELIMIT_QPS},
    "cloudProviderRateLimitBucket": ${CLOUDPROVIDER_RATELIMIT_BUCKET},
    "cloudProviderRateLimitQPSWrite": ${CLOUDPROVIDER_RATELIMIT_QPS_WRITE},
    "cloudProviderRateLimitBucketWrite": ${CLOUDPROVIDER_RATELIMIT_BUCKET_WRITE},
    "useManagedIdentityExtension": ${USE_MANAGED_IDENTITY_EXTENSION},
    "userAssignedIdentityID": "${USER_ASSIGNED_IDENTITY_ID}",
    "useInstanceMetadata": ${USE_INSTANCE_METADATA},
    "loadBalancerSku": "${LOAD_BALANCER_SKU}",
    "disableOutboundSNAT": ${LOAD_BALANCER_DISABLE_OUTBOUND_SNAT},
    "excludeMasterFromStandardLB": ${EXCLUDE_MASTER_FROM_STANDARD_LB},
    "providerVaultName": "${KMS_PROVIDER_VAULT_NAME}",
    "maximumLoadBalancerRuleCount": ${MAXIMUM_LOADBALANCER_RULE_COUNT},
    "providerKeyName": "k8s",
    "providerKeyVersion": ""
}
EOF
    set -x
    if [[ "${CLOUDPROVIDER_BACKOFF_MODE}" = "v2" ]]; then
        sed -i "/cloudProviderBackoffExponent/d" /etc/kubernetes/azure.json
        sed -i "/cloudProviderBackoffJitter/d" /etc/kubernetes/azure.json
    fi

    configureKubeletServerCert
{{- if IsAKSCustomCloud}}
    set +x
    AKS_CUSTOM_CLOUD_JSON_PATH="/etc/kubernetes/{{GetTargetEnvironment}}.json"
    touch "${AKS_CUSTOM_CLOUD_JSON_PATH}"
    chmod 0600 "${AKS_CUSTOM_CLOUD_JSON_PATH}"
    chown root:root "${AKS_CUSTOM_CLOUD_JSON_PATH}"

    cat << EOF > "${AKS_CUSTOM_CLOUD_JSON_PATH}"
{
    "name": "{{GetTargetEnvironment}}",
    "managementPortalURL": "{{AKSCustomCloudManagementPortalURL}}",
    "publishSettingsURL": "{{AKSCustomCloudPublishSettingsURL}}",
    "serviceManagementEndpoint": "{{AKSCustomCloudServiceManagementEndpoint}}",
    "resourceManagerEndpoint": "{{AKSCustomCloudResourceManagerEndpoint}}",
    "activeDirectoryEndpoint": "{{AKSCustomCloudActiveDirectoryEndpoint}}",
    "galleryEndpoint": "{{AKSCustomCloudGalleryEndpoint}}",
    "keyVaultEndpoint": "{{AKSCustomCloudKeyVaultEndpoint}}",
    "graphEndpoint": "{{AKSCustomCloudGraphEndpoint}}",
    "serviceBusEndpoint": "{{AKSCustomCloudServiceBusEndpoint}}",
    "batchManagementEndpoint": "{{AKSCustomCloudBatchManagementEndpoint}}",
    "storageEndpointSuffix": "{{AKSCustomCloudStorageEndpointSuffix}}",
    "sqlDatabaseDNSSuffix": "{{AKSCustomCloudSqlDatabaseDNSSuffix}}",
    "trafficManagerDNSSuffix": "{{AKSCustomCloudTrafficManagerDNSSuffix}}",
    "keyVaultDNSSuffix": "{{AKSCustomCloudKeyVaultDNSSuffix}}",
    "serviceBusEndpointSuffix": "{{AKSCustomCloudServiceBusEndpointSuffix}}",
    "serviceManagementVMDNSSuffix": "{{AKSCustomCloudServiceManagementVMDNSSuffix}}",
    "resourceManagerVMDNSSuffix": "{{AKSCustomCloudResourceManagerVMDNSSuffix}}",
    "containerRegistryDNSSuffix": "{{AKSCustomCloudContainerRegistryDNSSuffix}}",
    "cosmosDBDNSSuffix": "{{AKSCustomCloudCosmosDBDNSSuffix}}",
    "tokenAudience": "{{AKSCustomCloudTokenAudience}}",
    "resourceIdentifiers": {
        "graph": "{{AKSCustomCloudResourceIdentifiersGraph}}",
        "keyVault": "{{AKSCustomCloudResourceIdentifiersKeyVault}}",
        "datalake": "{{AKSCustomCloudResourceIdentifiersDatalake}}",
        "batch": "{{AKSCustomCloudResourceIdentifiersBatch}}",
        "operationalInsights": "{{AKSCustomCloudResourceIdentifiersOperationalInsights}}",
        "storage": "{{AKSCustomCloudResourceIdentifiersStorage}}"
    }
}
EOF
    set -x
{{end}}

{{- if IsKubeletConfigFileEnabled}}
    set +x
    KUBELET_CONFIG_JSON_PATH="/etc/default/kubeletconfig.json"
    touch "${KUBELET_CONFIG_JSON_PATH}"
    chmod 0644 "${KUBELET_CONFIG_JSON_PATH}"
    chown root:root "${KUBELET_CONFIG_JSON_PATH}"
    cat << EOF > "${KUBELET_CONFIG_JSON_PATH}"
{{GetKubeletConfigFileContent}}
EOF
    set -x
{{- end}}
}

configureCNI() {
    {{/* needed for the iptables rules to work on bridges */}}
    retrycmd_if_failure 120 5 25 modprobe br_netfilter || exit $ERR_MODPROBE_FAIL
    echo -n "br_netfilter" > /etc/modules-load.d/br_netfilter.conf
    configureCNIIPTables
}

customizeCNI() {
    {{- if IsAzureStackCloud}}
    if [[ "${NETWORK_PLUGIN}" = "azure" ]]; then
        generateIPAMFileSource
        local temp=$(mktemp)
        cp $CNI_CONFIG_DIR/10-azure.conflist ${temp}
        jq '.plugins[0].ipam.environment = "mas"' ${temp} > $CNI_CONFIG_DIR/10-azure.conflist
    fi
    {{end}}
}

configureCNIIPTables() {
    if [[ "${NETWORK_PLUGIN}" = "azure" ]]; then
        mv $CNI_BIN_DIR/10-azure.conflist $CNI_CONFIG_DIR/
        chmod 600 $CNI_CONFIG_DIR/10-azure.conflist
        if [[ "${NETWORK_POLICY}" == "calico" ]]; then
          sed -i 's#"mode":"bridge"#"mode":"transparent"#g' $CNI_CONFIG_DIR/10-azure.conflist
        elif [[ "${NETWORK_POLICY}" == "" || "${NETWORK_POLICY}" == "none" ]] && [[ "${NETWORK_MODE}" == "transparent" ]]; then
          sed -i 's#"mode":"bridge"#"mode":"transparent"#g' $CNI_CONFIG_DIR/10-azure.conflist
        fi
        /sbin/ebtables -t nat --list
    fi
}

{{- if IsAzureStackCloud}}
generateIPAMFileSource() {
    NETWORK_INTERFACES_FILE="/etc/kubernetes/network_interfaces.json"
    AZURE_CNI_CONFIG_FILE="/etc/kubernetes/interfaces.json"
    AZURESTACK_ENVIRONMENT_JSON_PATH="/etc/kubernetes/azurestackcloud.json"
    AZURE_JSON_PATH="/etc/kubernetes/azure.json"
    NETWORK_API_VERSION="2018-08-01"

    SERVICE_MANAGEMENT_ENDPOINT=$(jq -r '.serviceManagementEndpoint' ${AZURESTACK_ENVIRONMENT_JSON_PATH})
    ACTIVE_DIRECTORY_ENDPOINT=$(jq -r '.activeDirectoryEndpoint' ${AZURESTACK_ENVIRONMENT_JSON_PATH})
    RESOURCE_MANAGER_ENDPOINT=$(jq -r '.resourceManagerEndpoint' ${AZURESTACK_ENVIRONMENT_JSON_PATH})
    TENANT_ID=$(jq -r '.tenantId' ${AZURE_JSON_PATH})
    TOKEN_URL=$(echo ${ACTIVE_DIRECTORY_ENDPOINT}${TENANT_ID}/oauth2/token)

    set +x
    TOKEN=$(curl -s --retry 5 --retry-delay 10 --max-time 60 -f -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=${SERVICE_PRINCIPAL_CLIENT_ID}" \
        --data-urlencode "client_secret=${SERVICE_PRINCIPAL_CLIENT_SECRET}" \
        --data-urlencode "resource=${SERVICE_MANAGEMENT_ENDPOINT}" \
        ${TOKEN_URL} | jq '.access_token' | xargs)

    if [[ -z ${TOKEN} ]]; then
        echo "Error generating token for Azure Resource Manager"
        exit ${ERR_ASH_GET_ARM_TOKEN}
    fi

    curl -s --retry 5 --retry-delay 10 --max-time 60 -f -X GET \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        "${RESOURCE_MANAGER_ENDPOINT}subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/networkInterfaces?api-version=${NETWORK_API_VERSION}" > ${NETWORK_INTERFACES_FILE}
    set -x

    if [[ ! -s ${NETWORK_INTERFACES_FILE} ]]; then
        echo "Error fetching network interface configuration for node"
        exit ${ERR_ASH_GET_NETWORK_CONFIGURATION}
    fi

    echo "Generating Azure CNI interface file"

    mapfile -t local_interfaces < <(cat /sys/class/net/*/address | tr -d : | sed 's/.*/\U&/g')

    SDN_INTERFACES=$(jq ".value | map(select(.properties != null) | select(.properties.macAddress != null) | select(.properties.macAddress | inside(\"${local_interfaces[*]}\"))) | map(select((.properties.ipConfigurations | length) > 0))" ${NETWORK_INTERFACES_FILE})

    if [[ -z ${SDN_INTERFACES} ]]; then
        echo "Error extracting the SDN interfaces from the network interfaces file"
        exit ${ERR_ASH_GET_SUBNET_PREFIX}
    fi

    AZURE_CNI_CONFIG=$(echo ${SDN_INTERFACES} | jq "{Interfaces: [.[] | {MacAddress: .properties.macAddress, IsPrimary: .properties.primary, IPSubnets: [{Prefix: .properties.ipConfigurations[0].properties.subnet.id, IPAddresses: .properties.ipConfigurations | [.[] | {Address: .properties.privateIPAddress, IsPrimary: .properties.primary}]}]}]}")

    mapfile -t SUBNET_IDS < <(echo ${SDN_INTERFACES} | jq '[.[].properties.ipConfigurations[0].properties.subnet.id] | unique | .[]' -r)

    for SUBNET_ID in "${SUBNET_IDS[@]}"; do
        SUBNET_PREFIX=$(curl -s --retry 5 --retry-delay 10 --max-time 60 -f -X GET \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            "${RESOURCE_MANAGER_ENDPOINT}${SUBNET_ID:1}?api-version=${NETWORK_API_VERSION}" |
            jq '.properties.addressPrefix' -r)

        if [[ -z ${SUBNET_PREFIX} ]]; then
            echo "Error fetching the subnet address prefix for a subnet ID"
            exit ${ERR_ASH_GET_SUBNET_PREFIX}
        fi

        AZURE_CNI_CONFIG=$(echo ${AZURE_CNI_CONFIG} | sed "s|${SUBNET_ID}|${SUBNET_PREFIX}|g")
    done

    echo ${AZURE_CNI_CONFIG} > ${AZURE_CNI_CONFIG_FILE}
    chmod 0444 ${AZURE_CNI_CONFIG_FILE}
}
{{end}}

disable1804SystemdResolved() {
    ls -ltr /etc/resolv.conf
    cat /etc/resolv.conf
    {{- if Disable1804SystemdResolved}}
    UBUNTU_RELEASE=$(lsb_release -r -s)
    if [[ ${UBUNTU_RELEASE} == "18.04" ]]; then
        echo "Ingorings systemd-resolved query service but using its resolv.conf file"
        echo "This is the simplest approach to workaround resolved issues without completely uninstall it"
        [ -f /run/systemd/resolve/resolv.conf ] && sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
        ls -ltr /etc/resolv.conf
        cat /etc/resolv.conf
    fi
    {{- else}}
    echo "Disable1804SystemdResolved is false. Skipping."
    {{- end}}
}

{{- if NeedsContainerd}}
ensureContainerd() {
  {{- if TeleportEnabled}}
  ensureTeleportd
  {{- end}}
  wait_for_file 1200 1 /etc/systemd/system/containerd.service.d/exec_start.conf || exit $ERR_FILE_WATCH_TIMEOUT
  wait_for_file 1200 1 /etc/containerd/config.toml || exit $ERR_FILE_WATCH_TIMEOUT
  wait_for_file 1200 1 /etc/sysctl.d/11-containerd.conf || exit $ERR_FILE_WATCH_TIMEOUT
  retrycmd_if_failure 120 5 25 sysctl --system || exit $ERR_SYSCTL_RELOAD
  systemctl is-active --quiet docker && (systemctl_disable 20 30 120 docker || exit $ERR_SYSTEMD_DOCKER_STOP_FAIL)
  systemctlEnableAndStart containerd || exit $ERR_SYSTEMCTL_START_FAIL
}
{{- if and IsKubenet (not HasCalicoNetworkPolicy)}}
ensureNoDupOnPromiscuBridge() {
    wait_for_file 1200 1 /opt/azure/containers/ensure-no-dup.sh || exit $ERR_FILE_WATCH_TIMEOUT
    wait_for_file 1200 1 /etc/systemd/system/ensure-no-dup.service || exit $ERR_FILE_WATCH_TIMEOUT
    systemctlEnableAndStart ensure-no-dup || exit $ERR_SYSTEMCTL_START_FAIL
}
{{- end}}
{{- if TeleportEnabled}}
ensureTeleportd() {
    wait_for_file 1200 1 /etc/systemd/system/teleportd.service || exit $ERR_FILE_WATCH_TIMEOUT
    systemctlEnableAndStart teleportd || exit $ERR_SYSTEMCTL_START_FAIL
}
{{- end}}
{{- end}}
{{- if NeedsDocker}}
ensureDocker() {
    DOCKER_SERVICE_EXEC_START_FILE=/etc/systemd/system/docker.service.d/exec_start.conf
    wait_for_file 1200 1 $DOCKER_SERVICE_EXEC_START_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    usermod -aG docker ${ADMINUSER}
    DOCKER_MOUNT_FLAGS_SYSTEMD_FILE=/etc/systemd/system/docker.service.d/clear_mount_propagation_flags.conf
    wait_for_file 1200 1 $DOCKER_MOUNT_FLAGS_SYSTEMD_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    DOCKER_JSON_FILE=/etc/docker/daemon.json
    for i in $(seq 1 1200); do
        if [ -s $DOCKER_JSON_FILE ]; then
            jq '.' < $DOCKER_JSON_FILE && break
        fi
        if [ $i -eq 1200 ]; then
            exit $ERR_FILE_WATCH_TIMEOUT
        else
            sleep 1
        fi
    done
    systemctl is-active --quiet containerd && (systemctl_disable 20 30 120 containerd || exit $ERR_SYSTEMD_CONTAINERD_STOP_FAIL)
    systemctlEnableAndStart docker || exit $ERR_DOCKER_START_FAIL

}
{{- end}}
{{- if NeedsContainerd}}
ensureMonitorService() {
    {{/* Delay start of containerd-monitor for 30 mins after booting */}}
    CONTAINERD_MONITOR_SYSTEMD_TIMER_FILE=/etc/systemd/system/containerd-monitor.timer
    wait_for_file 1200 1 $CONTAINERD_MONITOR_SYSTEMD_TIMER_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    CONTAINERD_MONITOR_SYSTEMD_FILE=/etc/systemd/system/containerd-monitor.service
    wait_for_file 1200 1 $CONTAINERD_MONITOR_SYSTEMD_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    systemctlEnableAndStart containerd-monitor.timer || exit $ERR_SYSTEMCTL_START_FAIL
}
{{- end}}
{{- if NeedsDocker}}
ensureMonitorService() {
    {{/* Delay start of docker-monitor for 30 mins after booting */}}
    DOCKER_MONITOR_SYSTEMD_TIMER_FILE=/etc/systemd/system/docker-monitor.timer
    wait_for_file 1200 1 $DOCKER_MONITOR_SYSTEMD_TIMER_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    DOCKER_MONITOR_SYSTEMD_FILE=/etc/systemd/system/docker-monitor.service
    wait_for_file 1200 1 $DOCKER_MONITOR_SYSTEMD_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    systemctlEnableAndStart docker-monitor.timer || exit $ERR_SYSTEMCTL_START_FAIL
}
{{- end}}
{{if EnableEncryptionWithExternalKms}}
ensureKMS() {
    systemctlEnableAndStart kms || exit $ERR_SYSTEMCTL_START_FAIL
}
{{end}}

{{if IsIPv6DualStackFeatureEnabled}}
ensureDHCPv6() {
    wait_for_file 3600 1 {{GetDHCPv6ServiceCSEScriptFilepath}} || exit $ERR_FILE_WATCH_TIMEOUT
    wait_for_file 3600 1 {{GetDHCPv6ConfigCSEScriptFilepath}} || exit $ERR_FILE_WATCH_TIMEOUT
    systemctlEnableAndStart dhcpv6 || exit $ERR_SYSTEMCTL_START_FAIL
    retrycmd_if_failure 120 5 25 modprobe ip6_tables || exit $ERR_MODPROBE_FAIL
}
{{end}}

ensureKubelet() {
    KUBELET_DEFAULT_FILE=/etc/default/kubelet
    wait_for_file 1200 1 $KUBELET_DEFAULT_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    {{if IsKubeletClientTLSBootstrappingEnabled -}}
    BOOTSTRAP_KUBECONFIG_FILE=/var/lib/kubelet/bootstrap-kubeconfig
    wait_for_file 1200 1 $BOOTSTRAP_KUBECONFIG_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    {{- else -}}
    KUBECONFIG_FILE=/var/lib/kubelet/kubeconfig
    wait_for_file 1200 1 $KUBECONFIG_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    {{- end}}
    KUBELET_RUNTIME_CONFIG_SCRIPT_FILE=/opt/azure/containers/kubelet.sh
    wait_for_file 1200 1 $KUBELET_RUNTIME_CONFIG_SCRIPT_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    {{- if ShouldConfigureHTTPProxy}}
    configureEtcEnvironment
    {{- end}}
    systemctlEnableAndStart kubelet || exit $ERR_KUBELET_START_FAIL
    {{if HasAntreaNetworkPolicy}}
    while [ ! -f /etc/cni/net.d/10-antrea.conf ]; do
        sleep 3
    done
    {{end}}
    {{if HasFlannelNetworkPlugin}}
    while [ ! -f /etc/cni/net.d/10-flannel.conf ]; do
        sleep 3
    done
    {{end}}
}

# The update-node-labels.service updates the labels for the kubernetes node. Runs until successful on startup
ensureUpdateNodeLabels() {
    KUBELET_DEFAULT_FILE=/etc/default/kubelet
    wait_for_file 1200 1 $KUBELET_DEFAULT_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    UPDATE_NODE_LABELS_SCRIPT_FILE=/opt/azure/containers/update-node-labels.sh
    wait_for_file 1200 1 $UPDATE_NODE_LABELS_SCRIPT_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    UPDATE_NODE_LABELS_SYSTEMD_FILE=/etc/systemd/system/update-node-labels.service
    wait_for_file 1200 1 $UPDATE_NODE_LABELS_SYSTEMD_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    systemctlEnableAndStart update-node-labels || exit $ERR_SYSTEMCTL_START_FAIL
}

ensureMigPartition(){
    systemctlEnableAndStart mig-partition || exit $ERR_SYSTEMCTL_START_FAIL
}

ensureSysctl() {
    SYSCTL_CONFIG_FILE=/etc/sysctl.d/999-sysctl-aks.conf
    wait_for_file 1200 1 $SYSCTL_CONFIG_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    retrycmd_if_failure 24 5 25 sysctl --system
}

ensureJournal() {
    {
        echo "Storage=persistent"
        echo "SystemMaxUse=1G"
        echo "RuntimeMaxUse=1G"
        echo "ForwardToSyslog=yes"
    } >> /etc/systemd/journald.conf
    systemctlEnableAndStart systemd-journald || exit $ERR_SYSTEMCTL_START_FAIL
}

ensureK8sControlPlane() {
    if $REBOOTREQUIRED || [ "$NO_OUTBOUND" = "true" ]; then
        return
    fi
    retrycmd_if_failure 120 5 25 $KUBECTL 2>/dev/null cluster-info || exit $ERR_K8S_RUNNING_TIMEOUT
}

createKubeManifestDir() {
    KUBEMANIFESTDIR=/etc/kubernetes/manifests
    mkdir -p $KUBEMANIFESTDIR
}

writeKubeConfig() {
    KUBECONFIGDIR=/home/$ADMINUSER/.kube
    KUBECONFIGFILE=$KUBECONFIGDIR/config
    mkdir -p $KUBECONFIGDIR
    touch $KUBECONFIGFILE
    chown $ADMINUSER:$ADMINUSER $KUBECONFIGDIR
    chown $ADMINUSER:$ADMINUSER $KUBECONFIGFILE
    chmod 700 $KUBECONFIGDIR
    chmod 600 $KUBECONFIGFILE
    set +x
    echo "
---
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: \"$CA_CERTIFICATE\"
    server: $KUBECONFIG_SERVER
  name: \"$MASTER_FQDN\"
contexts:
- context:
    cluster: \"$MASTER_FQDN\"
    user: \"$MASTER_FQDN-admin\"
  name: \"$MASTER_FQDN\"
current-context: \"$MASTER_FQDN\"
kind: Config
users:
- name: \"$MASTER_FQDN-admin\"
  user:
    client-certificate-data: \"$KUBECONFIG_CERTIFICATE\"
    client-key-data: \"$KUBECONFIG_KEY\"
" > $KUBECONFIGFILE
    set -x
}

configClusterAutoscalerAddon() {
    CLUSTER_AUTOSCALER_ADDON_FILE=/etc/kubernetes/addons/cluster-autoscaler-deployment.yaml
    wait_for_file 1200 1 $CLUSTER_AUTOSCALER_ADDON_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    sed -i "s|<clientID>|$(echo $SERVICE_PRINCIPAL_CLIENT_ID | base64)|g" $CLUSTER_AUTOSCALER_ADDON_FILE
    sed -i "s|<clientSec>|$(echo $SERVICE_PRINCIPAL_CLIENT_SECRET | base64)|g" $CLUSTER_AUTOSCALER_ADDON_FILE
    sed -i "s|<subID>|$(echo $SUBSCRIPTION_ID | base64)|g" $CLUSTER_AUTOSCALER_ADDON_FILE
    sed -i "s|<tenantID>|$(echo $TENANT_ID | base64)|g" $CLUSTER_AUTOSCALER_ADDON_FILE
    sed -i "s|<rg>|$(echo $RESOURCE_GROUP | base64)|g" $CLUSTER_AUTOSCALER_ADDON_FILE
}

configACIConnectorAddon() {
    ACI_CONNECTOR_CREDENTIALS=$(printf "{\"clientId\": \"%s\", \"clientSecret\": \"%s\", \"tenantId\": \"%s\", \"subscriptionId\": \"%s\", \"activeDirectoryEndpointUrl\": \"https://login.microsoftonline.com\",\"resourceManagerEndpointUrl\": \"https://management.azure.com/\", \"activeDirectoryGraphResourceId\": \"https://graph.windows.net/\", \"sqlManagementEndpointUrl\": \"https://management.core.windows.net:8443/\", \"galleryEndpointUrl\": \"https://gallery.azure.com/\", \"managementEndpointUrl\": \"https://management.core.windows.net/\"}" "$SERVICE_PRINCIPAL_CLIENT_ID" "$SERVICE_PRINCIPAL_CLIENT_SECRET" "$TENANT_ID" "$SUBSCRIPTION_ID" | base64 -w 0)

    openssl req -newkey rsa:4096 -new -nodes -x509 -days 3650 -keyout /etc/kubernetes/certs/aci-connector-key.pem -out /etc/kubernetes/certs/aci-connector-cert.pem -subj "/C=US/ST=CA/L=virtualkubelet/O=virtualkubelet/OU=virtualkubelet/CN=virtualkubelet"
    ACI_CONNECTOR_KEY=$(base64 /etc/kubernetes/certs/aci-connector-key.pem -w0)
    ACI_CONNECTOR_CERT=$(base64 /etc/kubernetes/certs/aci-connector-cert.pem -w0)

    ACI_CONNECTOR_ADDON_FILE=/etc/kubernetes/addons/aci-connector-deployment.yaml
    wait_for_file 1200 1 $ACI_CONNECTOR_ADDON_FILE || exit $ERR_FILE_WATCH_TIMEOUT
    sed -i "s|<creds>|$ACI_CONNECTOR_CREDENTIALS|g" $ACI_CONNECTOR_ADDON_FILE
    sed -i "s|<rgName>|$RESOURCE_GROUP|g" $ACI_CONNECTOR_ADDON_FILE
    sed -i "s|<cert>|$ACI_CONNECTOR_CERT|g" $ACI_CONNECTOR_ADDON_FILE
    sed -i "s|<key>|$ACI_CONNECTOR_KEY|g" $ACI_CONNECTOR_ADDON_FILE
}

configAzurePolicyAddon() {
    AZURE_POLICY_ADDON_FILE=/etc/kubernetes/addons/azure-policy-deployment.yaml
    sed -i "s|<resourceId>|/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP|g" $AZURE_POLICY_ADDON_FILE
}

{{if IsNSeriesSKU}}
installGPUDriversRun() {
    {{- /* there is no file under the module folder, the installation failed, so clean up the dirty directory
    when you upgrade the GPU driver version, please help check whether the retry installation issue is gone,
    if yes please help remove the clean up logic here too */}}
    set -x
    MODULE_NAME="nvidia"
    NVIDIA_DKMS_DIR="/var/lib/dkms/${MODULE_NAME}/${GPU_DV}"
    KERNEL_NAME=$(uname -r)
    if [ -d "${NVIDIA_DKMS_DIR}" ]; then
        if [ -x "$(command -v dkms)" ]; then
          dkms remove -m ${MODULE_NAME} -v ${GPU_DV} -k ${KERNEL_NAME}
        else
          rm -rf "${NVIDIA_DKMS_DIR}"
        fi
    fi
    {{- /* we need to append the date to the end of the file because the retry will override the log file */}}
    local log_file_name="/var/log/nvidia-installer-$(date +%s).log"
    if [ ! -f "${GPU_DEST}/nvidia-drivers-${GPU_DV}" ]; then
        installGPUDrivers
    fi
    sh $GPU_DEST/nvidia-drivers-$GPU_DV -s \
        -k=$KERNEL_NAME \
        --log-file-name=${log_file_name} \
        -a --no-drm --dkms --utility-prefix="${GPU_DEST}" --opengl-prefix="${GPU_DEST}"
    exit $?
}

configGPUDrivers() {
    {{/* only install the runtime since nvidia-docker2 has a hard dep on docker CE packages. */}}
    {{/* we will manually install nvidia-docker2 */}}
    rmmod nouveau
    echo blacklist nouveau >> /etc/modprobe.d/blacklist.conf
    retrycmd_if_failure_no_stats 120 5 25 update-initramfs -u || exit $ERR_GPU_DRIVERS_INSTALL_TIMEOUT
    wait_for_apt_locks
    {{/* if the unattened upgrade is turned on, and it may takes 10 min to finish the installation, and we use the 1 second just to try to get the lock more aggressively */}}
    retrycmd_if_failure 600 1 3600 apt-get -o Dpkg::Options::="--force-confold" install -y nvidia-container-runtime="${NVIDIA_CONTAINER_RUNTIME_VERSION}+${NVIDIA_DOCKER_SUFFIX}" || exit $ERR_GPU_DRIVERS_INSTALL_TIMEOUT
    tmpDir=$GPU_DEST/tmp
    (
      set -e -o pipefail
      cd "${tmpDir}"
      wait_for_apt_locks
      dpkg-deb -R ./nvidia-docker2*.deb "${tmpDir}/pkg" || exit $ERR_GPU_DRIVERS_INSTALL_TIMEOUT
      cp -r ${tmpDir}/pkg/usr/* /usr/ || exit $ERR_GPU_DRIVERS_INSTALL_TIMEOUT
    )
    rm -rf $GPU_DEST/tmp
    {{if NeedsContainerd}}
    retrycmd_if_failure 120 5 25 pkill -SIGHUP containerd || exit $ERR_GPU_DRIVERS_INSTALL_TIMEOUT
    {{end}}
    {{if NeedsDocker}}
    retrycmd_if_failure 120 5 25 pkill -SIGHUP dockerd || exit $ERR_GPU_DRIVERS_INSTALL_TIMEOUT
    {{end}}
    mkdir -p $GPU_DEST/lib64 $GPU_DEST/overlay-workdir
    retrycmd_if_failure 120 5 25 mount -t overlay -o lowerdir=/usr/lib/x86_64-linux-gnu,upperdir=${GPU_DEST}/lib64,workdir=${GPU_DEST}/overlay-workdir none /usr/lib/x86_64-linux-gnu || exit $ERR_GPU_DRIVERS_INSTALL_TIMEOUT
    export -f installGPUDriversRun
    retrycmd_if_failure 3 1 600 bash -c installGPUDriversRun || exit $ERR_GPU_DRIVERS_START_FAIL
    mv ${GPU_DEST}/bin/* /usr/bin
    echo "${GPU_DEST}/lib64" > /etc/ld.so.conf.d/nvidia.conf
    retrycmd_if_failure 120 5 25 ldconfig || exit $ERR_GPU_DRIVERS_START_FAIL
    umount -l /usr/lib/x86_64-linux-gnu
    retrycmd_if_failure 120 5 25 nvidia-modprobe -u -c0 || exit $ERR_GPU_DRIVERS_START_FAIL
    retrycmd_if_failure 120 5 25 nvidia-smi || exit $ERR_GPU_DRIVERS_START_FAIL
    retrycmd_if_failure 120 5 25 ldconfig || exit $ERR_GPU_DRIVERS_START_FAIL
}

validateGPUDrivers() {
    retrycmd_if_failure 24 5 25 nvidia-modprobe -u -c0 && echo "gpu driver loaded" || configGPUDrivers || exit $ERR_GPU_DRIVERS_START_FAIL
    which nvidia-smi
    if [[ $? == 0 ]]; then
        SMI_RESULT=$(retrycmd_if_failure 24 5 25 nvidia-smi)
    else
        SMI_RESULT=$(retrycmd_if_failure 24 5 25 $GPU_DEST/bin/nvidia-smi)
    fi
    SMI_STATUS=$?
    if [[ $SMI_STATUS != 0 ]]; then
        if [[ $SMI_RESULT == *"infoROM is corrupted"* ]]; then
            exit $ERR_GPU_INFO_ROM_CORRUPTED
        else
            exit $ERR_GPU_DRIVERS_START_FAIL
        fi
    else
        echo "gpu driver working fine"
    fi
}

ensureGPUDrivers() {
    if [[ "${CONFIG_GPU_DRIVER_IF_NEEDED}" = true ]]; then
        configGPUDrivers
    else
        validateGPUDrivers
    fi
    systemctlEnableAndStart nvidia-modprobe || exit $ERR_GPU_DRIVERS_START_FAIL
}
{{end}}
#EOF
