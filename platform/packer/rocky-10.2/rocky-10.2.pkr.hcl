packer {
  required_version = "= 1.16.1"
  required_plugins {
    virtualbox = {
      source  = "github.com/hashicorp/virtualbox"
      version = "= 1.1.5"
    }
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "= 1.1.6"
    }
    vagrant = {
      source  = "github.com/hashicorp/vagrant"
      version = "= 1.1.7"
    }
  }
}

variable "iso_url" {
  type = string
}

variable "iso_checksum" {
  type      = string
  sensitive = true
}

variable "build_password" {
  type      = string
  sensitive = true
}

locals {
  boot_command = [
    "<up><wait><tab><wait>",
    " inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/rocky-10.2.ks",
    "<enter>",
  ]
}

source "virtualbox-iso" "base" {
  vm_name              = "ecommerce-rocky-10.2-base"
  guest_os_type        = "RedHat_64"
  iso_url              = var.iso_url
  iso_checksum         = "sha256:${var.iso_checksum}"
  http_directory       = "${path.root}/http"
  boot_command         = local.boot_command
  boot_wait            = "10s"
  ssh_username         = "packer"
  ssh_password         = var.build_password
  ssh_timeout          = "30m"
  shutdown_command     = "true"
  guest_additions_mode = "disable"
  disk_size            = 32768
  cpus                 = 2
  memory               = 4096
  hard_drive_interface = "sata"
  format               = "ova"
  output_directory     = "${path.root}/../../../.context/packer/rocky-10.2-virtualbox"
}

source "qemu" "base" {
  vm_name          = "ecommerce-rocky-10.2-base"
  iso_url          = var.iso_url
  iso_checksum     = "sha256:${var.iso_checksum}"
  http_directory   = "${path.root}/http"
  boot_command     = local.boot_command
  boot_wait        = "10s"
  ssh_username     = "packer"
  ssh_password     = var.build_password
  ssh_timeout      = "30m"
  shutdown_command = "true"
  accelerator      = "kvm"
  disk_size        = "32G"
  disk_interface   = "virtio"
  format           = "qcow2"
  cpus             = 2
  memory           = 4096
  net_device       = "virtio-net"
  output_directory = "${path.root}/../../../.context/packer/rocky-10.2-kvm"
}

build {
  name = "rocky-10.2-base"
  sources = [
    "source.virtualbox-iso.base",
    "source.qemu.base",
  ]

  provisioner "file" {
    source      = "${path.root}/../../../.context/packer/rocky-10.2-rpms"
    destination = "/tmp/rocky-10.2-rpms"
  }

  provisioner "shell" {
    execute_command = "echo '${var.build_password}' | sudo -S env {{ .Vars }} {{ .Path }}"
    inline = [
      "set -eu",
      "rpm --import /tmp/rocky-10.2-rpms/keys/*.asc",
      "dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 install /tmp/rocky-10.2-rpms/packages/*.rpm",
      "rpm -q kernel-modules-extra container-selinux NetworkManager openssh-server python3 chrony nftables iptables-nft conntrack-tools",
      "rpm -q qemu-guest-agent",
      "! rpm -q firewalld",
      "test \"$(getenforce)\" = Enforcing",
      "find /lib/modules -maxdepth 1 -mindepth 1 -type d -name '6.12.*' | grep -q .",
      "systemctl is-enabled sshd chronyd NetworkManager",
      "test -z \"$(swapon --noheadings --show)\"",
      "modprobe overlay && modprobe br_netfilter && modprobe nf_conntrack && modprobe vxlan",
      "sysctl -q net.ipv4.ip_forward | grep -q '= 1'",
      "test \"$(stat -fc %T /sys/fs/cgroup)\" = cgroup2fs",
      "grep -qw bpf /proc/filesystems && test -d /sys/fs/bpf",
      "command -v rg && command -v fd && command -v fzf && command -v yq && command -v bat && command -v tmux && command -v conntrack",
      "hostnamectl set-hostname rocky-10-2-base",
      "sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/10-ecommerce-base.conf",
      "truncate -s 0 /etc/machine-id",
      "rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*",
      "rm -rf /tmp/rocky-10.2-rpms",
      "usermod --password '!' packer",
      "systemd-run --unit=packer-final-shutdown --on-active=10s /usr/sbin/shutdown -P now",
      "rm -f /etc/sudoers.d/packer /home/packer/.ssh/authorized_keys",
      "dnf clean all",
    ]
  }

  post-processor "vagrant" {
    only              = ["virtualbox-iso.base"]
    output            = "${path.root}/../../../.context/packer/rocky-10.2-virtualbox.box"
    provider_override = "virtualbox"
  }
}
