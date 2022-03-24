#!/bin/bash

OS=$(sort -r /etc/*-release | gawk 'match($0, /^(ID_LIKE=(coreos)|ID=(.*))$/, a) { print toupper(a[2] a[3]); exit }')
UBUNTU_OS_NAME="UBUNTU"
MARINER_OS_NAME="MARINER"
THIS_DIR="$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)"

#the following sed removes all comments of the format {{/* */}}
sed -i 's/{{\/\*[^*]*\*\/}}//g' /home/packer/provision_source.sh
sed -i 's/{{\/\*[^*]*\*\/}}//g' /home/packer/tool_installs_distro.sh

source /home/packer/provision_installs.sh
source /home/packer/provision_installs_distro.sh
source /home/packer/provision_source.sh
source /home/packer/provision_source_distro.sh
source /home/packer/tool_installs.sh
source /home/packer/tool_installs_distro.sh
source /home/packer/packer_source.sh

VHD_LOGS_FILEPATH=/opt/azure/vhd-install.complete
COMPONENTS_FILEPATH=/opt/azure/components.json
KUBE_PROXY_IMAGES_FILEPATH=/opt/azure/kube-proxy-images.json
#this is used by post build test to check whether the compoenents do indeed exist
cat components.json > ${COMPONENTS_FILEPATH}
cat ${THIS_DIR}/kube-proxy-images.json > ${KUBE_PROXY_IMAGES_FILEPATH}
echo "Starting build on " $(date) > ${VHD_LOGS_FILEPATH}

if [[ $OS == $MARINER_OS_NAME ]]; then
  chmod 755 /opt
  chmod 755 /opt/azure
  chmod 644 ${VHD_LOGS_FILEPATH}
fi

copyPackerFiles

echo ""
echo "Components downloaded in this VHD build (some of the below components might get deleted during cluster provisioning if they are not needed):" >> ${VHD_LOGS_FILEPATH}

installDeps
cat << EOF >> ${VHD_LOGS_FILEPATH}
  - apache2-utils
  - apt-transport-https
  - blobfuse=1.3.7
  - ca-certificates
  - ceph-common
  - cgroup-lite
  - cifs-utils
  - conntrack
  - cracklib-runtime
  - ebtables
  - ethtool
  - fuse
  - git
  - glusterfs-client
  - init-system-helpers
  - iproute2
  - ipset
  - iptables
  - jq
  - libpam-pwquality
  - libpwquality-tools
  - mount
  - nfs-common
  - pigz socat
  - traceroute
  - util-linux
  - xz-utils
  - zip
  - chrony
  - vlock
  - auditd
  - ssh
  - libpam-pkcs11 
  - aide 
  - opensc-pkcs11 
  - libpam-apparmor
EOF

if [[ ${UBUNTU_RELEASE} == "18.04" && ${ENABLE_FIPS,,} == "true" ]]; then
  installFIPS
elif [[ ${ENABLE_FIPS,,} == "true" ]]; then
  echo "AKS enables FIPS on Ubuntu 18.04 only, exiting..."
  exit 1
fi

if [[ ${UBUNTU_RELEASE} == "18.04" ]]; then
  overrideNetworkConfig || exit 1
  disableNtpAndTimesyncdInstallChrony || exit 1
fi

if [[ $OS == $MARINER_OS_NAME ]]; then
    disableSystemdResolvedCache
    disableSystemdIptables
    forceEnableIpForward
    networkdWorkaround
fi

if [[ ${CONTAINER_RUNTIME:-""} == "containerd" ]]; then
  echo "VHD will be built with containerd as the container runtime"
  containerd_version="1.4.12"
  installStandaloneContainerd ${containerd_version}
  echo "  - [installed] containerd v${containerd_version}" >> ${VHD_LOGS_FILEPATH}
  if [[ $OS == $UBUNTU_OS_NAME ]]; then
    # also pre-cache containerd 1.4.4 (last used version)
    containerd_version="1.4.4"
    downloadContainerd ${containerd_version}
    echo "  - [cached] containerd v${containerd_version}" >> ${VHD_LOGS_FILEPATH}
  fi
  NERDCTL_VERSIONS="
  0.17.1
  "
  for NERDCTL_VERSION in ${NERDCTL_VERSIONS}; do
    downloadNerdctl ${NERDCTL_VERSION}
    echo "  - nerdctl version ${NERDCTL_VERSION}" >> ${VHD_LOGS_FILEPATH}
  done
  CRICTL_VERSIONS="
  1.20.0
  1.21.0
  "
  for CRICTL_VERSION in ${CRICTL_VERSIONS}; do
    downloadCrictl ${CRICTL_VERSION}
    echo "  - crictl version ${CRICTL_VERSION}" >> ${VHD_LOGS_FILEPATH}
  done
  # k8s will use images in the k8s.io namespaces - create it
  ctr namespace create k8s.io
  cliTool="ctr"

  # also pre-download Teleportd plugin for containerd
  # downloadTeleportdPlugin ${TELEPORTD_PLUGIN_DOWNLOAD_URL} "0.6.0"
fi

INSTALLED_RUNC_VERSION=$(runc --version | head -n1 | sed 's/runc version //')
echo "  - runc version ${INSTALLED_RUNC_VERSION}" >> ${VHD_LOGS_FILEPATH}

## for ubuntu-based images, cache multiple versions of runc
if [[ $OS == $UBUNTU_OS_NAME ]]; then
  RUNC_VERSIONS="
  1.0.0-rc95
  1.0.3
  "
  for RUNC_VERSION in $RUNC_VERSIONS; do
    downloadDebPkgToFile "moby-runc" ${RUNC_VERSION/\-/\~} ${RUNC_DOWNLOADS_DIR}
    echo "  - [cached] runc ${RUNC_VERSION}" >> ${VHD_LOGS_FILEPATH}
  done
fi

installImg
echo "  - img" >> ${VHD_LOGS_FILEPATH}

echo "${CONTAINER_RUNTIME} images pre-pulled:" >> ${VHD_LOGS_FILEPATH}

string_replace() {
  echo ${1//\*/$2}
}

ContainerImages=$(jq ".ContainerImages" $COMPONENTS_FILEPATH | jq .[] --monochrome-output --compact-output)
for imageToBePulled in ${ContainerImages[*]}; do
  downloadURL=$(echo "${imageToBePulled}" | jq .downloadURL -r)
  versions=$(echo "${imageToBePulled}" | jq .versions -r | jq -r ".[]")

  for version in ${versions}; do
    CONTAINER_IMAGE=$(string_replace $downloadURL $version)
    pullContainerImage ${cliTool} ${CONTAINER_IMAGE}
    echo "  - ${CONTAINER_IMAGE}" >> ${VHD_LOGS_FILEPATH}
  done
done

VNET_CNI_VERSIONS="
1.4.14
1.4.21
"
for VNET_CNI_VERSION in $VNET_CNI_VERSIONS; do
    VNET_CNI_PLUGINS_URL="https://acs-mirror.azureedge.net/azure-cni/v${VNET_CNI_VERSION}/binaries/azure-vnet-cni-linux-amd64-v${VNET_CNI_VERSION}.tgz"
    downloadAzureCNI
    echo "  - Azure CNI version ${VNET_CNI_VERSION}" >> ${VHD_LOGS_FILEPATH}
done

CNI_PLUGIN_VERSIONS="
0.9.1
"

for CNI_PLUGIN_VERSION in $CNI_PLUGIN_VERSIONS; do
    CNI_PLUGINS_URL="https://acs-mirror.azureedge.net/cni-plugins/v${CNI_PLUGIN_VERSION}/binaries/cni-plugins-linux-amd64-v${CNI_PLUGIN_VERSION}.tgz"
    downloadCNI
    echo "  - CNI plugin version ${CNI_PLUGIN_VERSION}" >> ${VHD_LOGS_FILEPATH}
done

NGINX_VERSIONS="1.13.12-alpine"
for NGINX_VERSION in ${NGINX_VERSIONS}; do
    if [[ "${cliTool}" == "ctr" ]]; then
      # containerd/ctr doesn't auto-resolve to docker.io
      CONTAINER_IMAGE="docker.io/library/nginx:${NGINX_VERSION}"
    else
      CONTAINER_IMAGE="nginx:${NGINX_VERSION}"
    fi
    pullContainerImage ${cliTool} ${CONTAINER_IMAGE}
    echo "  - ${CONTAINER_IMAGE}" >> ${VHD_LOGS_FILEPATH}
done

# this is used by kube-proxy and need to cover previously supported version for VMAS scale up scenario
# So keeping as many versions as we can - those unsupported version can be removed when we don't have enough space
# below are the required to support versions
# v1.20.13
# v1.21.7
# v1.21.4
# NOTE that we keep multiple files per k8s patch version as kubeproxy version is decided by CCP.

if [[ ${CONTAINER_RUNTIME} == "containerd" ]]; then
  KUBE_PROXY_IMAGE_VERSIONS=$(jq -r '.containerdKubeProxyImages.ContainerImages[0].versions[]' <"$THIS_DIR/kube-proxy-images.json")
else
  KUBE_PROXY_IMAGE_VERSIONS=$(jq -r '.dockerKubeProxyImages.ContainerImages[0].versions[]' <"$THIS_DIR/kube-proxy-images.json")
fi

for KUBE_PROXY_IMAGE_VERSION in ${KUBE_PROXY_IMAGE_VERSIONS}; do
  # use kube-proxy as well
  CONTAINER_IMAGE="mcr.microsoft.com/oss/kubernetes/kube-proxy:v${KUBE_PROXY_IMAGE_VERSION}"
  pullContainerImage ${cliTool} ${CONTAINER_IMAGE}
  if [[ ${cliTool} == "docker" ]]; then
      docker run --rm --entrypoint "" ${CONTAINER_IMAGE} /bin/sh -c "iptables --version" | grep -v nf_tables && echo "kube-proxy contains no nf_tables"
  else
      ctr --namespace k8s.io run --rm ${CONTAINER_IMAGE} checkTask /bin/sh -c "iptables --version" | grep -v nf_tables && echo "kube-proxy contains no nf_tables"
  fi
  # shellcheck disable=SC2181
  if [[ $? != 0 ]]; then
  echo "Hyperkube contains nf_tables, exiting..."
  exit 99
  fi
  echo "  - ${CONTAINER_IMAGE}" >>${VHD_LOGS_FILEPATH}
done

# kubelet and kubectl
# need to cover previously supported version for VMAS scale up scenario
# So keeping as many versions as we can - those unsupported version can be removed when we don't have enough space
# below are the required to support versions
# v1.20.13
# v1.21.7
# NOTE that we only keep the latest one per k8s patch version as kubelet/kubectl is decided by VHD version
# Please do not use the .1 suffix, because that's only for the base image patches
KUBE_BINARY_VERSIONS="
1.20.13-azs
1.21.7-azs
"
for PATCHED_KUBE_BINARY_VERSION in ${KUBE_BINARY_VERSIONS}; do
  if (($(echo ${PATCHED_KUBE_BINARY_VERSION} | cut -d"." -f2) < 19)) && [[ ${CONTAINER_RUNTIME} == "containerd" ]]; then
    echo "Only need to store k8s components >= 1.19 for containerd VHDs"
    continue
  fi
  KUBERNETES_VERSION=$(echo ${PATCHED_KUBE_BINARY_VERSION} | cut -d"_" -f1 | cut -d"-" -f1 | cut -d"." -f1,2,3)
  extractKubeBinaries $KUBERNETES_VERSION "https://acs-mirror.azureedge.net/kubernetes/v${PATCHED_KUBE_BINARY_VERSION}/binaries/kubernetes-node-linux-amd64.tar.gz"
done

# shellcheck disable=SC2129
echo "kubelet/kubectl downloaded:" >> ${VHD_LOGS_FILEPATH}
ls -ltr /usr/local/bin/* >> ${VHD_LOGS_FILEPATH}

# shellcheck disable=SC2010
ls -ltr /dev/* | grep sgx >>  ${VHD_LOGS_FILEPATH} 

echo -e "=== Installed Packages Begin\n$(listInstalledPackages)\n=== Installed Packages End" >> ${VHD_LOGS_FILEPATH}

echo "Disk usage:" >> ${VHD_LOGS_FILEPATH}
df -h >> ${VHD_LOGS_FILEPATH}
# warn at 75% space taken
[ -s $(df -P | grep '/dev/sda1' | awk '0+$5 >= 75 {print}') ] || echo "WARNING: 75% of /dev/sda1 is used" >> ${VHD_LOGS_FILEPATH}
# error at 99% space taken
[ -s $(df -P | grep '/dev/sda1' | awk '0+$5 >= 99 {print}') ] || exit 1

echo "Using kernel:" >> ${VHD_LOGS_FILEPATH}
tee -a ${VHD_LOGS_FILEPATH} < /proc/version
{
  echo "Install completed successfully on " $(date)
  echo "VSTS Build NUMBER: ${BUILD_NUMBER}"
  echo "VSTS Build ID: ${BUILD_ID}"
  echo "Commit: ${COMMIT}"
  echo "Ubuntu version: ${UBUNTU_RELEASE}"
  echo "Hyperv generation: ${HYPERV_GENERATION}"
  echo "Feature flags: ${FEATURE_FLAGS}"
  echo "Container runtime: ${CONTAINER_RUNTIME}"
  echo "FIPS enabled: ${ENABLE_FIPS}"
} >> ${VHD_LOGS_FILEPATH}

installAscBaseline

if [[ ${UBUNTU_RELEASE} == "18.04" && ${ENABLE_FIPS,,} == "true" ]]; then
  relinkResolvConf
fi

# remove snapd, which is not used by container stack
apt-get purge --auto-remove snapd -y

# update message-of-the-day to start after multi-user.target
# multi-user.target usually start at the end of the boot sequence
sed -i 's/After=network-online.target/After=multi-user.target/g' /lib/systemd/system/motd-news.service

# retag all the mcr for mooncake
# shellcheck disable=SC2207
allMCRImages=($(docker images | grep '^mcr.microsoft.com/' | awk '{str = sprintf("%s:%s", $1, $2)} {print str}'))
for mcrImage in "${allMCRImages[@]}"; do
  # in mooncake, the mcr endpoint is: mcr.azk8s.cn
  # shellcheck disable=SC2001
  retagMCRImage=$(echo ${mcrImage} | sed -e 's/^mcr.microsoft.com/mcr.azk8s.cn/g')
  retagContainerImage ${cliTool} ${mcrImage} ${retagMCRImage}
done
