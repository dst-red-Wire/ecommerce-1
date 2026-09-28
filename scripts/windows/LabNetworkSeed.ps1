function Get-LabPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try { $listener.Start(); return [int]$listener.LocalEndpoint.Port }
    finally { $listener.Stop() }
}

function Write-LabSeed {
    param([string]$Root, [string]$Campaign, [string]$PublicKey)
    if ($PublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+=* ecommerce-lab-rocky-smoke$') {
        throw 'Persistent laboratory SSH public key format is invalid'
    }
    $seed = Join-Path $Root 'seed'
    [void](New-Item -ItemType Directory -Path $seed -Force)
    [IO.File]::WriteAllText((Join-Path $seed 'meta-data'), "instance-id: ecommerce-rocky-smoke-$Campaign`nlocal-hostname: rocky-smoke`n", [Text.UTF8Encoding]::new($false))
    $userData = @"
#cloud-config
disable_root: true
ssh_pwauth: false
package_update: false
package_upgrade: false
users:
  - name: packer
    lock_passwd: true
    ssh_authorized_keys:
      - $PublicKey
write_files:
  - path: /home/packer/.ssh/authorized_keys
    owner: packer:packer
    permissions: '0600'
    content: |
      $PublicKey
runcmd:
  - [chown, -R, 'packer:packer', /home/packer/.ssh]
  - [chmod, '0700', /home/packer/.ssh]
  - [chmod, '0600', /home/packer/.ssh/authorized_keys]
  - [restorecon, -RF, /home/packer/.ssh]
"@
    [IO.File]::WriteAllText((Join-Path $seed 'user-data'), $userData + "`n", [Text.UTF8Encoding]::new($false))
    return $seed
}
