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

locals {
  image_name = "rocky-10.2-${var.image_profile}"
  vm_name    = "ecommerce-rocky-10-2-build-${var.image_profile}"
  boot_command = [
    "c<wait5>",
    "linux /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=Rocky-10-2-x86_64-dvd inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/rocky-10.2.ks<enter><wait>",
    "initrd /images/pxeboot/initrd.img<enter><wait>",
    "boot<enter>",
  ]
}

source "virtualbox-iso" "base" {
  vm_name       = local.vm_name
  guest_os_type = "RedHat_64"
  iso_url       = var.iso_url
  iso_checksum  = "sha256:${var.iso_checksum}"
  http_content = {
    "/rocky-10.2.ks" = templatefile("${abspath(path.root)}/http/rocky-10.2.ks", {
      build_ssh_public_key = trimspace(var.build_ssh_public_key)
      partition_table      = var.vm_partition_table
      bios_boot_mib        = var.vm_bios_boot_mib
      boot_mib             = var.vm_boot_mib
      root_min_mib         = var.vm_root_min_mib
      root_filesystem      = var.vm_root_filesystem
    })
  }
  boot_command           = local.boot_command
  boot_keygroup_interval = "500ms"
  boot_wait              = "10s"
  ssh_username           = "packer"
  ssh_private_key_file   = var.build_ssh_private_key_file
  ssh_timeout            = "${var.vm_ssh_timeout_seconds}s"
  shutdown_command       = "true"
  guest_additions_mode   = "disable"
  headless               = var.vm_headless
  firmware               = var.vm_firmware
  disk_size              = var.vm_disk_mib
  cpus                   = var.vm_cpus
  memory                 = var.vm_memory_mib
  hard_drive_interface   = "sata"
  format                 = "ova"
  output_directory       = "${var.artifact_dir}/${local.image_name}-virtualbox"
}

source "qemu" "base" {
  vm_name      = local.vm_name
  iso_url      = var.iso_url
  iso_checksum = "sha256:${var.iso_checksum}"
  http_content = {
    "/rocky-10.2.ks" = templatefile("${abspath(path.root)}/http/rocky-10.2.ks", {
      build_ssh_public_key = trimspace(var.build_ssh_public_key)
      partition_table      = var.vm_partition_table
      bios_boot_mib        = var.vm_bios_boot_mib
      boot_mib             = var.vm_boot_mib
      root_min_mib         = var.vm_root_min_mib
      root_filesystem      = var.vm_root_filesystem
    })
  }
  boot_command         = local.boot_command
  boot_key_interval    = "100ms"
  boot_wait            = "10s"
  ssh_username         = "packer"
  ssh_private_key_file = var.build_ssh_private_key_file
  ssh_timeout          = "${var.vm_ssh_timeout_seconds}s"
  shutdown_command     = "true"
  accelerator          = "kvm"
  headless             = var.vm_headless
  efi_boot             = var.vm_firmware == "efi"
  disk_size            = "${var.vm_disk_mib}M"
  disk_interface       = "virtio"
  format               = "qcow2"
  cpus                 = var.vm_cpus
  memory               = var.vm_memory_mib
  net_device           = "virtio-net"
  output_directory     = "${var.artifact_dir}/${local.image_name}-kvm"
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
      "dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 --allowerasing install /tmp/packer-offline/rpms/base/*.rpm",
      "python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --rpm-profile base",
      "cd /tmp/packer-offline/tools/base && sha256sum --check SHA256SUMS",
      "python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --profile base",
      "if [ \"$IMAGE_PROFILE\" = rke2 ]; then cd /tmp/packer-offline/rpms/rke2 && sha256sum --check SHA256SUMS && dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 --allowerasing install /tmp/packer-offline/rpms/rke2/*.rpm && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --rpm-profile rke2; cd /tmp/packer-offline/tools/rke2 && sha256sum --check SHA256SUMS && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --profile rke2; fi",
      "if [ \"$PACKER_BUILDER_TYPE\" = qemu ]; then cd /tmp/packer-offline/rpms/qemu-kvm && sha256sum --check SHA256SUMS && dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 --allowerasing install /tmp/packer-offline/rpms/qemu-kvm/*.rpm && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --rpm-profile qemu-kvm && systemctl enable qemu-guest-agent; else ! rpm -q qemu-guest-agent; fi",
      "if [ \"$IMAGE_PROFILE\" = admin-qualification ]; then cd /tmp/packer-offline/rpms/admin-qualification && sha256sum --check SHA256SUMS && dnf -y --disablerepo='*' --setopt=localpkg_gpgcheck=1 --allowerasing install /tmp/packer-offline/rpms/admin-qualification/*.rpm && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --rpm-profile admin-qualification; cd /tmp/packer-offline/tools/admin-qualification && sha256sum --check SHA256SUMS && python3 /tmp/packer-offline/install_tools.py --bundle /tmp/packer-offline --profile admin-qualification; fi",
      "rpm -q kernel-modules-extra container-selinux NetworkManager openssh-server python3 chrony nftables iptables-nft conntrack-tools",
      "! rpm -q firewalld",
      "test \"$(getenforce)\" = Enforcing",
      "find /lib/modules -maxdepth 1 -mindepth 1 -type d -name '6.12.*' | grep -q .",
      "grubby --default-kernel | grep -Fq '6.12.0-211.58.1.el10_2.x86_64'",
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
      "if [ \"$IMAGE_PROFILE\" = rke2 ]; then oscap --version && test -r /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml && kube-bench version; else ! command -v oscap && ! command -v kube-bench && ! rpm -q scap-security-guide; fi",
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
      "passwd --status packer | grep -Eq '^packer[[:space:]]+L'",
      "test -s /home/packer/.ssh/authorized_keys",
      "chmod 0700 /home/packer/.ssh && chmod 0600 /home/packer/.ssh/authorized_keys",
      "systemd-run --unit=packer-final-shutdown --on-active=10s /usr/sbin/shutdown -P now",
    ]
  }

  post-processor "vagrant" {
    only              = ["virtualbox-iso.base"]
    output            = "${var.artifact_dir}/${local.image_name}-virtualbox.box"
    provider_override = "virtualbox"
  }
}
