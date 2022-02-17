#!/bin/bash

touch /etc/audit/rules.d/stig.rules
chmod 0640 /etc/audit/rules.d/stig.rules
patch --ignore-whitespace /etc/audit/rules.d/stig.rules < /opt/azure/containers/patches/stig.rules.patch

# touch /etc/issue
# chmod 0644 /etc/issue
# patch --ignore-whitespace /etc/issue < /opt/azure/containers/patches/issue.patch

touch /etc/modprobe.d/DISASTIG.conf
chmod 0600 /etc/modprobe.d/DISASTIG.conf
patch --ignore-whitespace /etc/modprobe.d/DISASTIG.conf < /opt/azure/containers/patches/DISASTIG.conf.patch

touch /etc/profile.d/autologout.sh
chmod 0600 /etc/profile.d/autologout.sh
patch --ignore-whitespace /etc/profile.d/autologout.sh < /opt/azure/containers/patches/autologout.sh.patch

patch --ignore-whitespace /etc/login.defs < /opt/azure/containers/patches/login.defs.patch
patch --ignore-whitespace /etc/apt/apt.conf.d/50unattended-upgrades < /opt/azure/containers/patches/50unattended-upgrades.patch
patch --ignore-whitespace /etc/audit/auditd.conf < /opt/azure/containers/patches/auditd.conf.patch
patch --ignore-whitespace /etc/security/limits.conf < /opt/azure/containers/patches/limits.conf.patch
patch --ignore-whitespace /etc/security/pwquality.conf < /opt/azure/containers/patches/pwquality.conf.patch
patch --ignore-whitespace /etc/ssh/sshd_config < /opt/azure/containers/patches/sshd_config.patch

augenrules --load

systemctl mask ctrl-alt-del.target
systemctl daemon-reload
systemctl restart sshd
systemctl restart auditd.service

#EOF
