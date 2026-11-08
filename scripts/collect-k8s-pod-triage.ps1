<#
.SYNOPSIS
    Read-only Kubernetes Pod Diagnostic Collector for CrashLoopBackOff and OOMKilled RCA.

.DESCRIPTION
    Collects read-only pod manifests, container previous termination logs, and
    namespace warning events using standard kubectl commands. Outputs a single
    structured JSON bundle for root-cause analysis.
    Pure PowerShell, zero third-party modules, zero cluster mutations.

.PARAMETER PodName
    Name of the Kubernetes Pod to inspect.

.PARAMETER Namespace
    Kubernetes namespace (default: default).

.PARAMETER LogLines
    Number of log tail lines per container (default: 150).

.PARAMETER OutputPath
    Output JSON file destination (default: ./k8s-pod-snapshot.json).

.EXAMPLE
    .\collect-k8s-pod-triage.ps1 -PodName "payments-api-6b8f9d-x2k4" -Namespace "production"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$PodName,

    [Parameter(Mandatory = $false)]
    [string]$Namespace = "default",

    [Parameter(Mandatory = $false)]
    [int]$LogLines = 150,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./k8s-pod-snapshot.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Error "kubectl is not installed or not available in the current PATH."
    exit 1
}

Write-Host "[*] Collecting read-only pod manifest for $Namespace/$PodName..."

$podJsonRaw = & kubectl get pod $PodName -n $Namespace -o json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to retrieve pod $PodName in namespace $Namespace`: $podJsonRaw"
    exit 1
}

$podObj = $podJsonRaw | ConvertFrom-Json

Write-Host "[*] Collecting namespace lifecycle events..."
$eventsRaw = & kubectl get events -n $Namespace --field-selector "involvedObject.name=$PodName" -o json 2>&1
$eventsObj = @()
if ($LASTEXITCODE -eq 0) {
    try {
        $parsedEvents = $eventsRaw | ConvertFrom-Json
        if ($parsedEvents.items) {
            foreach ($item in $parsedEvents.items) {
                $eventsObj += "$($item.type) $($item.reason): $($item.message)"
            }
        }
    } catch {
        Write-Warning "Could not parse event JSON stream."
    }
}

Write-Host "[*] Collecting previous container termination logs..."
$previousLogs = @{}
$currentLogs = @{}

if ($podObj.spec.containers) {
    foreach ($c in $podObj.spec.containers) {
        $cName = $c.name
        
        # Previous termination log
        $prevRaw = & kubectl logs $PodName -n $Namespace -c $cName --previous --tail=$LogLines 2>&1
        if ($LASTEXITCODE -eq 0) {
            $previousLogs[$cName] = ($prevRaw -join "`n")
        } else {
            $previousLogs[$cName] = "No previous container log available (container may not have restarted)."
        }

        # Current container log
        $curRaw = & kubectl logs $PodName -n $Namespace -c $cName --tail=$LogLines 2>&1
        if ($LASTEXITCODE -eq 0) {
            $currentLogs[$cName] = ($curRaw -join "`n")
        }
    }
}

$snapshot = [ordered]@{
    collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    namespace = $Namespace
    pod_name = $PodName
    pod_spec_and_status = $podObj
    events = $eventsObj
    previous_logs = $previousLogs
    current_logs = $currentLogs
}

$jsonOutput = $snapshot | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($OutputPath, $jsonOutput, [System.Text.Encoding]::UTF8)

Write-Host "[+] Successfully saved read-only diagnostic snapshot to: $OutputPath"

