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

variable "build_ssh_public_key" {
  type      = string
  sensitive = true

  validation {
    condition     = can(regex("^ssh-(ed25519|rsa) [A-Za-z0-9+/]+={0,3}(?: [A-Za-z0-9._@-]+)?$", trimspace(var.build_ssh_public_key)))
    error_message = "The build SSH public key must contain one OpenSSH public key."
  }
}

variable "build_ssh_private_key_file" {
  type      = string
  sensitive = true

  validation {
    condition     = length(trimspace(var.build_ssh_private_key_file)) > 0
    error_message = "The build SSH private key file must reference the runtime-injected private key."
  }
}

variable "offline_bundle_dir" {
  type = string
}

variable "image_profile" {
  type    = string
  default = "rke2"

  validation {
    condition     = contains(["rke2", "admin-qualification"], var.image_profile)
    error_message = "Image_profile must be rke2 or admin-qualification."
  }
}

locals {
  image_name = "rocky-10.2-${var.image_profile}"
  boot_command = [
    "<up><wait><tab><wait>",
    " inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/rocky-10.2.ks",
    "<enter>",
  ]
}

source "virtualbox-iso" "base" {
  vm_name       = "ecommerce-${local.image_name}"
  guest_os_type = "RedHat_64"
  iso_url       = var.iso_url
  iso_checksum  = "sha256:${var.iso_checksum}"
  http_content = {
    "/rocky-10.2.ks" = templatefile("${abspath(path.root)}/http/rocky-10.2.ks", {
      build_ssh_public_key = trimspace(var.build_ssh_public_key)
    })
  }
  boot_command         = local.boot_command
  boot_wait            = "10s"
  ssh_username         = "packer"
  ssh_private_key_file = var.build_ssh_private_key_file
  ssh_timeout          = "30m"
  shutdown_command     = "true"
  guest_additions_mode = "disable"
  disk_size            = 32768
  cpus                 = 2
  memory               = 4096
  hard_drive_interface = "sata"
  format               = "ova"
  output_directory     = "${path.root}/../../../.context/packer/${local.image_name}-virtualbox"
}

source "qemu" "base" {
  vm_name      = "ecommerce-${local.image_name}"
  iso_url      = var.iso_url
  iso_checksum = "sha256:${var.iso_checksum}"
  http_content = {
    "/rocky-10.2.ks" = templatefile("${abspath(path.root)}/http/rocky-10.2.ks", {
      build_ssh_public_key = trimspace(var.build_ssh_public_key)
    })
  }
  boot_command         = local.boot_command
  boot_wait            = "10s"
  ssh_username         = "packer"
  ssh_private_key_file = var.build_ssh_private_key_file
  ssh_timeout          = "30m"
  shutdown_command     = "true"
  accelerator          = "kvm"
  disk_size            = "32G"
  disk_interface       = "virtio"
  format               = "qcow2"
  cpus                 = 2
  memory               = 4096
  net_device           = "virtio-net"
  output_directory     = "${path.root}/../../../.context/packer/${local.image_name}-kvm"
}

build {
  name = "rocky-10.2-base"
  sources = [
    "source.virtualbox-iso.base",
    "source.qemu.base",
  ]

  provisioner "shell" {
    inline = ["install -d -m 0700 /tmp/packer-offline"]
  }

  provisioner "file" {
    source      = "${var.offline_bundle_dir}/rpm-keys"
    destination = "/tmp/packer-offline"
  }

  provisioner "file" {
    source      = "${var.offline_bundle_dir}/rpms"
    destination = "/tmp/packer-offline"
  }

  provisioner "file" {
    source      = "${var.offline_bundle_dir}/tools"
    destination = "/tmp/packer-offline"
  }

  provisioner "file" {
    source      = "${var.offline_bundle_dir}/install_tools.py"
    destination = "/tmp/packer-offline/install_tools.py"
  }

  provisioner "shell" {
    execute_command  = "sudo -n env {{ .Vars }} {{ .Path }}"
    environment_vars = ["IMAGE_PROFILE=${var.image_profile}"]
    inline = [
      "set -eu",
      "cd /tmp/packer-offline/rpm-keys && sha256sum --check SHA256SUMS",
      "rpm --import /tmp/packer-offline/rpm-keys/*.asc",
      "cd /tmp/packer-offline/rpms/base && sha256sum --check SHA256SUMS",
      "dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 install /tmp/packer-offline/rpms/base/*.rpm",
      "python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --rpm-profile base",
      "cd /tmp/packer-offline/tools/base && sha256sum --check SHA256SUMS",
      "python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --profile base",
      "if [ \"$PACKER_BUILDER_TYPE\" = qemu ]; then cd /tmp/packer-offline/rpms/qemu-kvm && sha256sum --check SHA256SUMS && dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 install /tmp/packer-offline/rpms/qemu-kvm/*.rpm && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --rpm-profile qemu-kvm && systemctl enable qemu-guest-agent; else ! rpm -q qemu-guest-agent; fi",
      "if [ \"$IMAGE_PROFILE\" = admin-qualification ]; then cd /tmp/packer-offline/rpms/admin-qualification && sha256sum --check SHA256SUMS && dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 install /tmp/packer-offline/rpms/admin-qualification/*.rpm && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --rpm-profile admin-qualification; cd /tmp/packer-offline/tools/admin-qualification && sha256sum --check SHA256SUMS && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --profile admin-qualification; fi",
      "rpm -q kernel-modules-extra container-selinux NetworkManager openssh-server python3 chrony nftables iptables-nft conntrack-tools",
      "! rpm -q firewalld",
      "test \"$(getenforce)\" = Enforcing",
      "find /lib/modules -maxdepth 1 -mindepth 1 -type d -name '6.12.*' | grep -q .",
      "systemctl is-enabled sshd chronyd NetworkManager",
      "test -z \"$(swapon --noheadings --show)\"",
      "! grep -Ev '^[[:space:]]*(#|$)' /etc/fstab | grep -qw swap",
      "modprobe overlay && modprobe br_netfilter && modprobe nf_conntrack && modprobe vxlan",
      "sysctl -q net.ipv4.ip_forward | grep -q '= 1'",
      "sysctl -q net.bridge.bridge-nf-call-iptables | grep -q '= 1'",
      "sysctl -q net.bridge.bridge-nf-call-ip6tables | grep -q '= 1'",
      "sysctl -q fs.inotify.max_user_instances | grep -q '= 8192'",
      "sysctl -q fs.inotify.max_user_watches | grep -q '= 524288'",
      "test \"$(stat -fc %T /sys/fs/cgroup)\" = cgroup2fs",
      "grep -qw bpf /proc/filesystems && test -d /sys/fs/bpf",
      "rg --version && fd --version && fzf --version && jq --version && yq --version && bat --version && tmux -V",
      "if [ \"$IMAGE_PROFILE\" = admin-qualification ]; then git --version && strace --version && sar -V && mtr --version && shellcheck --version && shfmt --version && gh --version; else ! command -v gh && ! command -v git && ! command -v strace && ! command -v sar && ! command -v mtr && ! command -v shellcheck && ! command -v shfmt; fi",
      "test ! -e /root/.config/gh/hosts.yml",
      "! find /home -path '*/.config/gh/hosts.yml' -type f -print -quit | grep -q .",
      "! env | cut -d= -f1 | grep -Eq '^(GH_TOKEN|GITHUB_TOKEN)$'",
      "! grep -RIlE '(gho_|ghp_|github_pat_|oauth_token)' /root /home 2>/dev/null | grep -q .",
      "! find /root /home -type f \\( -name id_rsa -o -name id_ed25519 \\) -print -quit | grep -q .",
      "hostnamectl set-hostname rocky-10-2-base",
      "sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config.d/10-ecommerce-base.conf",
      "dnf clean all",
      "rm -f /var/lib/NetworkManager/*.lease /var/lib/dhclient/*",
      "rm -rf /root/.cache /home/packer/.cache",
      "truncate -s 0 /etc/machine-id",
      "rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*",
      "rm -rf /tmp/packer-offline",
      "usermod --lock --shell /sbin/nologin packer",
      "rm -f /etc/sudoers.d/packer && rm -rf /home/packer/.ssh",
      "systemd-run --unit=packer-final-shutdown --on-active=10s /usr/sbin/shutdown -P now",
    ]
  }

  post-processor "vagrant" {
    only              = ["virtualbox-iso.base"]
    output            = "${path.root}/../../../.context/packer/${local.image_name}-virtualbox.box"
    provider_override = "virtualbox"
  }
}
