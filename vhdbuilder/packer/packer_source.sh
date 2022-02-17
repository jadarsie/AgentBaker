#!/bin/bash

copyPackerFiles() {
  SYSCTL_CONFIG_SRC=/home/packer/sysctl-d-60-CIS.conf
  SYSCTL_CONFIG_DEST=/etc/sysctl.d/60-CIS.conf
  RSYSLOG_CONFIG_SRC=/home/packer/rsyslog-d-60-CIS.conf
  RSYSLOG_CONFIG_DEST=/etc/rsyslog.d/60-CIS.conf
  ETC_ISSUE_CONFIG_SRC=/home/packer/etc-issue
  ETC_ISSUE_CONFIG_DEST=/etc/issue
  ETC_ISSUE_NET_CONFIG_SRC=/home/packer/etc-issue.net
  ETC_ISSUE_NET_CONFIG_DEST=/etc/issue.net
  SSHD_CONFIG_SRC=/home/packer/sshd_config
  SSHD_CONFIG_DEST=/etc/ssh/sshd_config
  MODPROBE_CIS_SRC=/home/packer/modprobe-CIS.conf
  MODPROBE_CIS_DEST=/etc/modprobe.d/CIS.conf
  PWQUALITY_CONF_SRC=/home/packer/pwquality-CIS.conf
  PWQUALITY_CONF_DEST=/etc/security/pwquality.conf
  PAM_D_COMMON_AUTH_SRC=/home/packer/pam-d-common-auth
  PAM_D_COMMON_AUTH_DEST=/etc/pam.d/common-auth
  PAM_D_COMMON_PASSWORD_SRC=/home/packer/pam-d-common-password
  PAM_D_COMMON_PASSWORD_DEST=/etc/pam.d/common-password
  PAM_D_SU_SRC=/home/packer/pam-d-su
  PAM_D_SU_DEST=/etc/pam.d/su
  PROFILE_D_CIS_SH_SRC=/home/packer/profile-d-cis.sh
  PROFILE_D_CIS_SH_DEST=/etc/profile.d/CIS.sh
  UPDATE_NODE_LABELS_SRC=/home/packer/update-node-labels.sh
  UPDATE_NODE_LABELS_DEST=/opt/azure/containers/update-node-labels.sh
  UPDATE_NODE_LABELS_SERVICE_SRC=/home/packer/update-node-labels.service
  UPDATE_NODE_LABELS_SERVICE_DEST=/etc/systemd/system/update-node-labels.service
  CIS_SRC=/home/packer/cis.sh
  CIS_DEST=/opt/azure/containers/provision_cis.sh
  APT_PREFERENCES_SRC=/home/packer/apt-preferences
  APT_PREFERENCES_DEST=/etc/apt/preferences
  KMS_SERVICE_SRC=/home/packer/kms.service
  KMS_SERVICE_DEST=/etc/systemd/system/kms.service
  HEALTH_MONITOR_SRC=/home/packer/health-monitor.sh
  HEALTH_MONITOR_DEST=/usr/local/bin/health-monitor.sh
  KUBELET_MONITOR_SERVICE_SRC=/home/packer/kubelet-monitor.service
  KUBELET_MONITOR_SERVICE_DEST=/etc/systemd/system/kubelet-monitor.service
  DOCKER_MONITOR_SERVICE_SRC=/home/packer/docker-monitor.service
  DOCKER_MONITOR_SERVICE_DEST=/etc/systemd/system/docker-monitor.service
  DOCKER_MONITOR_TIMER_SRC=/home/packer/docker-monitor.timer
  DOCKER_MONITOR_TIMER_DEST=/etc/systemd/system/docker-monitor.timer
  CONTAINERD_MONITOR_SERVICE_SRC=/home/packer/containerd-monitor.service
  CONTAINERD_MONITOR_SERVICE_DEST=/etc/systemd/system/containerd-monitor.service
  CONTAINERD_MONITOR_TIMER_SRC=/home/packer/containerd-monitor.timer
  CONTAINERD_MONITOR_TIMER_DEST=/etc/systemd/system/containerd-monitor.timer
  KUBELET_SERVICE_SRC=/home/packer/kubelet.service
  KUBELET_SERVICE_DEST=/etc/systemd/system/kubelet.service
  DOCKER_CLEAR_MOUNT_PROPAGATION_FLAGS_SRC=/home/packer/docker_clear_mount_propagation_flags.conf
  DOCKER_CLEAR_MOUNT_PROPAGATION_FLAGS_DEST=/etc/systemd/system/docker.service.d/clear_mount_propagation_flags.conf
  NVIDIA_MODPROBE_SERVICE_SRC=/home/packer/nvidia-modprobe.service
  NVIDIA_MODPROBE_SERVICE_DEST=/etc/systemd/system/nvidia-modprobe.service
  NVIDIA_DOCKER_DAEMON_SRC=/home/packer/nvidia-docker-daemon.json
  NVIDIA_DOCKER_DAEMON_DEST=/etc/systemd/system/nvidia-docker-daemon.json
  NVIDIA_DEVICE_PLUGIN_SERVICE_SRC=/home/packer/nvidia-device-plugin.service
  NVIDIA_DEVICE_PLUGIN_SERVICE_DEST=/etc/systemd/system/nvidia-device-plugin.service
  AUDIT_POLICY_SRC=/home/packer/audit-policy.yaml
  AUDIT_POLICY_DEST=/etc/kubernetes/audit/audit-policy.yaml
  AZUREDISK_CSI_DRIVER_SRC=/home/packer/azuredisk-csi-driver.yaml
  AZUREDISK_CSI_DRIVER_DST=/etc/kubernetes/addons/azuredisk-csi-driver.yaml
  COREDNS_CONFIGMAP_SRC=/home/packer/coredns-custom-configmap.yaml
  COREDNS_CONFIGMAP_DST=/etc/kubernetes/addons/coredns-custom-configmap.yaml
  IP_MASQ_AGENT_SRC=/home/packer/ip-masq-agent.yaml
  IP_MASQ_AGENT_DST=/etc/kubernetes/addons/ip-masq-agent.yaml
  KUBE_METRICS_SERVER_SRC=/home/packer/kube-metrics-server.yaml
  KUBE_METRICS_SERVER_DST=/etc/kubernetes/addons/kube-metrics-server.yaml
  KUBE_STATE_METRICS_SRC=/home/packer/kube-state-metrics.yaml
  KUBE_STATE_METRICS_DST=/etc/kubernetes/addons/kube-state-metrics.yaml
  POD_SECURITY_POLICY_SRC=/home/packer/pod-security-policy.yaml
  POD_SECURITY_POLICY_DST=/etc/kubernetes/addons/psp.yaml
  AZURE_NETWORK_POLICY_SRC=/home/packer/azure-network-policy.yaml
  AZURE_NETWORK_POLICY_DST=/etc/kubernetes/addons/azure-network-policy.yaml
  NOTICE_SRC=/home/packer/NOTICE.txt
  NOTICE_DEST=/NOTICE.txt
  STIG_SRC=/home/packer/stig.sh
  STIG_DEST=/opt/azure/containers/stig.sh
  STIG_PATCH01_SRC=/home/packer/patches/50unattended-upgrades.patch
  STIG_PATCH01_DEST=/opt/azure/containers/patches/50unattended-upgrades.patch
  STIG_PATCH02_SRC=/home/packer/patches/auditd.conf.patch
  STIG_PATCH02_DEST=/opt/azure/containers/patches/auditd.conf.patch
  STIG_PATCH03_SRC=/home/packer/patches/autologout.sh.patch
  STIG_PATCH03_DEST=/opt/azure/containers/patches/autologout.sh.patch
  STIG_PATCH04_SRC=/home/packer/patches/DISASTIG.conf.patch
  STIG_PATCH04_DEST=/opt/azure/containers/patches/DISASTIG.conf.patch
  STIG_PATCH05_SRC=/home/packer/patches/issue.patch
  STIG_PATCH05_DEST=/opt/azure/containers/patches/issue.patch
  STIG_PATCH06_SRC=/home/packer/patches/limits.conf.patch
  STIG_PATCH06_DEST=/opt/azure/containers/patches/limits.conf.patch
  STIG_PATCH07_SRC=/home/packer/patches/login.defs.patch
  STIG_PATCH07_DEST=/opt/azure/containers/patches/login.defs.patch
  STIG_PATCH08_SRC=/home/packer/patches/pwquality.conf.patch
  STIG_PATCH08_DEST=/opt/azure/containers/patches/pwquality.conf.patch
  STIG_PATCH09_SRC=/home/packer/patches/sshd_config.patch
  STIG_PATCH09_DEST=/opt/azure/containers/patches/sshd_config.patch
  STIG_PATCH10_SRC=/home/packer/patches/stig.rules.patch
  STIG_PATCH10_DEST=/opt/azure/containers/patches/stig.rules.patch

  if [[ ${UBUNTU_RELEASE} == "16.04" ]]; then
    SSHD_CONFIG_SRC=/home/packer/sshd_config_1604
  elif [[ ${UBUNTU_RELEASE} == "18.04" && ${ENABLE_FIPS,,} == "true" ]]; then
    SSHD_CONFIG_SRC=/home/packer/sshd_config_1804_fips
  fi
  cpAndMode $SYSCTL_CONFIG_SRC $SYSCTL_CONFIG_DEST 644
  cpAndMode $RSYSLOG_CONFIG_SRC $RSYSLOG_CONFIG_DEST 644
  cpAndMode $ETC_ISSUE_CONFIG_SRC $ETC_ISSUE_CONFIG_DEST 644
  cpAndMode $ETC_ISSUE_NET_CONFIG_SRC $ETC_ISSUE_NET_CONFIG_DEST 644
  cpAndMode $SSHD_CONFIG_SRC $SSHD_CONFIG_DEST 644
  cpAndMode $MODPROBE_CIS_SRC $MODPROBE_CIS_DEST 644
  cpAndMode $PWQUALITY_CONF_SRC $PWQUALITY_CONF_DEST 600
  cpAndMode $PAM_D_COMMON_AUTH_SRC $PAM_D_COMMON_AUTH_DEST 644
  cpAndMode $PAM_D_COMMON_PASSWORD_SRC $PAM_D_COMMON_PASSWORD_DEST 644
  cpAndMode $PAM_D_SU_SRC $PAM_D_SU_DEST 644
  cpAndMode $PROFILE_D_CIS_SH_SRC $PROFILE_D_CIS_SH_DEST 755
  cpAndMode $UPDATE_NODE_LABELS_SRC $UPDATE_NODE_LABELS_DEST 744
  cpAndMode $UPDATE_NODE_LABELS_SERVICE_SRC $UPDATE_NODE_LABELS_SERVICE_DEST 644
  cpAndMode $CIS_SRC $CIS_DEST 744
  cpAndMode $APT_PREFERENCES_SRC $APT_PREFERENCES_DEST 644
  cpAndMode $KMS_SERVICE_SRC $KMS_SERVICE_DEST 644
  cpAndMode $HEALTH_MONITOR_SRC $HEALTH_MONITOR_DEST 544
  cpAndMode $KUBELET_MONITOR_SERVICE_SRC $KUBELET_MONITOR_SERVICE_DEST 644
  cpAndMode $CONTAINERD_MONITOR_SERVICE_SRC $CONTAINERD_MONITOR_SERVICE_DEST 644
  cpAndMode $CONTAINERD_MONITOR_TIMER_SRC $CONTAINERD_MONITOR_TIMER_DEST 644
  cpAndMode $KUBELET_SERVICE_SRC $KUBELET_SERVICE_DEST 644
  if [[ $OS != $MARINER_OS_NAME ]]; then
    cpAndMode $DOCKER_MONITOR_SERVICE_SRC $DOCKER_MONITOR_SERVICE_DEST 644
    cpAndMode $DOCKER_MONITOR_TIMER_SRC $DOCKER_MONITOR_TIMER_DEST 644
    cpAndMode $DOCKER_CLEAR_MOUNT_PROPAGATION_FLAGS_SRC $DOCKER_CLEAR_MOUNT_PROPAGATION_FLAGS_DEST 644
  fi
  if grep -q "fullgpu" <<< "$FEATURE_FLAGS"; then
    cpAndMode $NVIDIA_MODPROBE_SERVICE_SRC $NVIDIA_MODPROBE_SERVICE_DEST 644
    cpAndMode $NVIDIA_DOCKER_DAEMON_SRC $NVIDIA_DOCKER_DAEMON_DEST 644
    if grep -q "gpudaemon" <<< "$FEATURE_FLAGS"; then
      cpAndMode $NVIDIA_DEVICE_PLUGIN_SERVICE_SRC $NVIDIA_DEVICE_PLUGIN_SERVICE_DEST 644
    fi
  fi

  cpAndMode $AUDIT_POLICY_SRC $AUDIT_POLICY_DEST 600
  cpAndMode $AZUREDISK_CSI_DRIVER_SRC $AZUREDISK_CSI_DRIVER_DST 600
  cpAndMode $COREDNS_CONFIGMAP_SRC $COREDNS_CONFIGMAP_DST 600
  cpAndMode $IP_MASQ_AGENT_SRC $IP_MASQ_AGENT_DST 600
  cpAndMode $KUBE_METRICS_SERVER_SRC $KUBE_METRICS_SERVER_DST 600
  cpAndMode $KUBE_STATE_METRICS_SRC $KUBE_STATE_METRICS_DST 600
  cpAndMode $POD_SECURITY_POLICY_SRC $POD_SECURITY_POLICY_DST 600
  cpAndMode $AZURE_NETWORK_POLICY_SRC $AZURE_NETWORK_POLICY_DST 600
  cpAndMode $NOTICE_SRC $NOTICE_DEST 444

  cpAndMode $STIG_SRC $STIG_DEST 744
  cpAndMode $STIG_PATCH01_SRC $STIG_PATCH01_DEST 444
  cpAndMode $STIG_PATCH02_SRC $STIG_PATCH02_DEST 444
  cpAndMode $STIG_PATCH03_SRC $STIG_PATCH03_DEST 444
  cpAndMode $STIG_PATCH04_SRC $STIG_PATCH04_DEST 444
  cpAndMode $STIG_PATCH05_SRC $STIG_PATCH05_DEST 444
  cpAndMode $STIG_PATCH06_SRC $STIG_PATCH06_DEST 444
  cpAndMode $STIG_PATCH07_SRC $STIG_PATCH07_DEST 444
  cpAndMode $STIG_PATCH08_SRC $STIG_PATCH08_DEST 444
  cpAndMode $STIG_PATCH09_SRC $STIG_PATCH09_DEST 444
  cpAndMode $STIG_PATCH10_SRC $STIG_PATCH10_DEST 444
}

cpAndMode() {
  src=$1; dest=$2; mode=$3
  DIR=$(dirname "$dest") && mkdir -p ${DIR} && cp $src $dest && chmod $mode $dest || exit $ERR_PACKER_COPY_FILE
}