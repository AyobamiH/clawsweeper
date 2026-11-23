# Read-only native Windows host capability and runner-isolation gate.
# This script never registers a runner, installs an application or changes host configuration.
[CmdletBinding()]
param(
    [ValidateSet('Inspect', 'Admit')]
    [string]$Mode = 'Inspect'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$edition = 'unknown'
$architecture = 'unknown'
$elevated = $false
$sandboxAvailable = $false
$hostPlatform = [Environment]::OSVersion.Platform.ToString()
try {
    $product = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $edition = [string]$product.EditionID
} catch { }
try {
    $architecture = [string][Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
} catch { }
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $elevated = [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
try {
    $sandboxPath = Join-Path $env:WINDIR 'System32\WindowsSandbox.exe'
    $sandboxAvailable = [bool](Test-Path -LiteralPath $sandboxPath -PathType Leaf)
} catch { }

# These are capability observations, not a verified VM/runner attestation.
$supportedEdition = $edition -match '^(Professional(?:Education|Workstation|SingleLanguage|N)?|Enterprise(?:S|SN|N)?|Education(?:N)?)$'
$reasons = New-Object System.Collections.Generic.List[string]
if ($hostPlatform -ne 'Win32NT') { $reasons.Add('not_native_windows') }
if ($architecture -ne 'AMD64') { $reasons.Add('native_amd64_required') }
if (-not $supportedEdition) { $reasons.Add('windows_edition_no_supported_sandbox') }
if (-not $sandboxAvailable) { $reasons.Add('disposable_windows_sandbox_not_available') }
if (-not $elevated) { $reasons.Add('owner_admin_feature_provisioning_unavailable') }

# A guest must be independently created, isolated, authenticated and attested by
# a dedicated driver. The bare host can never accept a PR-triggered JIT runner.
$reasons.Add('disposable_guest_execution_not_independently_attested')

$report = [ordered]@{
    schema = 'clawsweeper.windows-native-preflight.v1'
    mode = $Mode
    host_platform = $hostPlatform
    windows_edition = $edition
    processor_arch = $architecture
    windows_sandbox_executable_present = $sandboxAvailable
    sandbox_edition_eligible = [bool]$supportedEdition
    interactive_admin_available = $elevated
    ephemeral_windows_guest_verified = $false
    github_runner_registration_performed = $false
    host_configuration_mutated = $false
    admitted = $false
    decision = 'HOLD_ISOLATED_WINDOWS_GUEST_REQUIRED'
    reasons = @($reasons.ToArray())
}
$report | ConvertTo-Json -Compress -Depth 5
if ($Mode -eq 'Admit') { exit 75 }
exit 0
