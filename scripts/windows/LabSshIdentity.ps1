[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Ensure', 'Verify')][string]$Action,
    [string]$IdentityRoot = 'C:\ecommerce-lab\identity'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RockyImagePipeline.psm1') -Force

function Assert-PrivateKeyAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.AreAccessRulesProtected -ne $true -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner.Value) {
        throw 'Persistent laboratory SSH private key owner or inheritance is unsafe'
    }
    $allowed = @($owner.Value, 'S-1-5-18', 'S-1-5-32-544')
    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {
            throw 'Persistent laboratory SSH private key is accessible to another principal'
        }
    }
}

$root = [IO.Path]::GetFullPath($IdentityRoot).TrimEnd('\')
$labRoot = [IO.Path]::GetFullPath('C:\ecommerce-lab').TrimEnd('\')
if ($root -ne (Join-Path $labRoot 'identity')) { throw 'Laboratory SSH identity root is outside the governed Windows lab root' }
$private = Join-Path $root 'id_ed25519'
$public = "$private.pub"
$sshKeygen = Resolve-WindowsTool -Name 'ssh-keygen.exe' -FallbackPaths @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'))
$privateExists = Test-Path -LiteralPath $private -PathType Leaf
$publicExists = Test-Path -LiteralPath $public -PathType Leaf
if ($privateExists -ne $publicExists) { throw 'Persistent laboratory SSH key pair is incomplete; refusing replacement' }
$status = 'REUSED'
if (-not $privateExists) {
    if ($Action -ne 'Ensure') { throw 'Persistent laboratory SSH identity is absent; run make lab-ssh-key explicitly' }
    [void](New-Item -ItemType Directory -Path $root -Force)
    $generated = Invoke-BoundedProcess -FilePath $sshKeygen -Arguments @('-q','-t','ed25519','-N','','-C','ecommerce-lab-rocky-smoke','-f',$private) -TimeoutSeconds 30 -WorkingDirectory $root
    Assert-ProcessSuccess -Result $generated -Operation 'explicit persistent laboratory SSH key generation'
    if (-not (Test-Path -LiteralPath $private -PathType Leaf) -or -not (Test-Path -LiteralPath $public -PathType Leaf)) {
        throw 'SSH key generation did not produce a complete pair'
    }
    $status = 'CREATED'
}
Assert-PrivateKeyAcl -Path $private
$derived = Invoke-BoundedProcess -FilePath $sshKeygen -Arguments @('-y','-f',$private) -TimeoutSeconds 15 -WorkingDirectory $root
Assert-ProcessSuccess -Result $derived -Operation 'persistent laboratory SSH private/public binding'
$expected = (([IO.File]::ReadAllText($public).Trim() -split '\s+') | Select-Object -First 2) -join ' '
$actual = (($derived.StdOut.Trim() -split '\s+') | Select-Object -First 2) -join ' '
if (-not $expected.StartsWith('ssh-ed25519 ') -or $actual -ne $expected) { throw 'Persistent laboratory SSH public key does not match its private key' }
$fingerprint = Invoke-BoundedProcess -FilePath $sshKeygen -Arguments @('-lf',$public) -TimeoutSeconds 15 -WorkingDirectory $root
Assert-ProcessSuccess -Result $fingerprint -Operation 'persistent laboratory SSH public fingerprint'
if ($fingerprint.StdOut -notmatch 'SHA256:([A-Za-z0-9+/]+)') { throw 'Persistent laboratory SSH fingerprint is invalid' }
[Console]::WriteLine("LAB_SSH_KEY=$status FINGERPRINT=SHA256:$($Matches[1])")
