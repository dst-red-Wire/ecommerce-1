text
cdrom
lang en_US.UTF-8
keyboard us
timezone UTC --utc
firstboot --disable
network --bootproto=dhcp --device=link --activate --hostname=rocky-10-2-base
rootpw --lock
user --name=packer --groups=wheel --lock
sshkey --username=packer "${build_ssh_public_key}"
selinux --enforcing
firewall --disabled
services --enabled=sshd,chronyd,NetworkManager
bootloader --location=mbr --append="${bootloader_kernel_arguments}"
zerombr
clearpart --all --initlabel --disklabel=${partition_table}
part biosboot --size=${bios_boot_mib}
part /boot --fstype=${root_filesystem} --size=${boot_mib}
part / --fstype=${root_filesystem} --size=${root_min_mib} --grow
reboot

%pre --erroronfail
if [ -c /dev/ttyS0 ]; then
    printf 'ECOMMERCE_MILESTONE T3_KICKSTART_START\n' > /dev/ttyS0
fi
if ! ip -4 -o address show scope global | grep -q ' inet '; then
    printf 'Kickstart network is not ready\n' >&2
    exit 1
fi
if [ -c /dev/ttyS0 ]; then
    printf 'ECOMMERCE_MILESTONE T4_NETWORK_READY\n' > /dev/ttyS0
    printf 'ECOMMERCE_MILESTONE T5_RPM_INSTALLATION_START\n' > /dev/ttyS0
fi
%end

%packages
@^minimal-environment
-firewalld
ca-certificates
chrony
kernel
kernel-modules
kernel-modules-extra
NetworkManager
openssh-server
python3
cloud-init
sudo
%end

%post --erroronfail
if [ -c /dev/ttyS0 ]; then
    printf 'ECOMMERCE_MILESTONE T6_RPM_INSTALLATION_END\n' > /dev/ttyS0
fi
echo 'packer ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/packer
chmod 0440 /etc/sudoers.d/packer
install -d -m 0700 -o packer -g packer /home/packer/.ssh

cat > /etc/ssh/sshd_config.d/10-ecommerce-base.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
EOF

cat > /etc/sysctl.d/90-kubernetes.conf <<'EOF'
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
fs.suid_dumpable = 0
EOF

cat > /etc/modules-load.d/kubernetes.conf <<'EOF'
overlay
br_netfilter
nf_conntrack
vxlan
EOF

swapoff -a
sed -ri '/\sswap\s/s/^/#/' /etc/fstab
systemctl disable --now firewalld 2>/dev/null || true
dnf -y remove firewalld || true

systemctl enable sshd chronyd NetworkManager

cat > /etc/systemd/system/packer-milestone-t8.service <<'EOF'
[Unit]
Description=Packer installed operating system boot milestone
DefaultDependencies=no
After=local-fs.target
Before=sshd.service
ConditionPathExists=/dev/ttyS0

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c "printf 'ECOMMERCE_MILESTONE T8_INSTALLED_OS_BOOT\n' > /dev/ttyS0"

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/packer-milestone-t9.service <<'EOF'
[Unit]
Description=Packer SSH readiness milestone
After=network-online.target sshd.service
Wants=network-online.target
ConditionPathExists=/dev/ttyS0

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c "printf 'ECOMMERCE_MILESTONE T9_SSHD_READY\n' > /dev/ttyS0"

[Install]
WantedBy=multi-user.target
EOF

systemctl enable packer-milestone-t8.service packer-milestone-t9.service
if [ -c /dev/ttyS0 ]; then
    printf 'ECOMMERCE_MILESTONE T7_FIRST_REBOOT\n' > /dev/ttyS0
fi
%end
