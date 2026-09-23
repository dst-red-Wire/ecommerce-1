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
bootloader --location=mbr --append="quiet console=tty0"
zerombr
clearpart --all --initlabel --disklabel=gpt
autopart --type=lvm
reboot

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
sudo
%end

%post --erroronfail
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
%end
