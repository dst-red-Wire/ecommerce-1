text
cdrom
lang en_US.UTF-8
keyboard us
timezone UTC --utc
firstboot --disable
network --bootproto=dhcp --device=link --activate --hostname=rocky-10-2-base
rootpw --lock
user --name=packer --groups=wheel --password=$6$rounds=656000$packerbuild$FrYdMXm2K0Vv9YbmGNnqsZXxaDmk6Ha6XyqD3hK8zJ7u/W35p99DCulLAmmlX8i3mxx6C7v3j51b.2DXgcbUd. --iscrypted
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
bash-completion
bind-utils
ca-certificates
chrony
conntrack-tools
container-selinux
curl
ethtool
file
gzip
iproute
iptables-nft
iputils
jq
kernel
kernel-core
kernel-modules
kernel-modules-extra
kmod
less
libnftnl
libselinux-utils
lsof
NetworkManager
nftables
openssh-server
policycoreutils
python3
qemu-guest-agent
rsync
selinux-policy
selinux-policy-targeted
tar
tcpdump
tmux
tree
unzip
which
xz
%end

%post --erroronfail
echo 'packer ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/packer
chmod 0440 /etc/sudoers.d/packer
install -d -m 0700 -o packer -g packer /home/packer/.ssh

cat > /etc/ssh/sshd_config.d/10-ecommerce-base.conf <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
EOF

cat > /etc/sysctl.d/60-ecommerce-base.conf <<'EOF'
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

cat > /etc/modules-load.d/60-kubernetes.conf <<'EOF'
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
