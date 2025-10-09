<# MARK: SYNOPSIS
    .SYNOPSIS
    Uninstalls applications registered in Programs and Features, App-V, or AppX/MSIX,
    with support for batch execution via JSON configuration.

    .DESCRIPTION
    Remove-App.ps1 searches registry uninstall keys (HKLM and HKU) for applications
    matching a provided DisplayName pattern, then executes the associated uninstall
    string. It also supports App-V and AppX/MSIX package removal. The script is
    designed for enterprise automation scenarios, with consistent logging, transcript
    capture, and safe testing (-WhatIf) capabilities.

    Features include:
      - Pattern-based matching of DisplayName values in Programs and Features
      - Support for App-V and AppX/MSIX (Store) package removal
      - Optional additional uninstall arguments via -Arguments
      - Per-job transcript logging with configurable path and filename
      - Customized JSON-driven batch jobs via -ConfigPath
      - Built-in catalog of uninstall recipes ready to use
      - Built-in support for -WhatIf and -Confirm for safe testing

    For parameters and usage examples, refer to the README
    
    .NOTES
    Author: Sean Estrella
    GitHub: https://github.com/e-sean
    LinkedIn: https://www.linkedin.com/in/seanestrella/

    Version: 1.0.4
#>

#####################################################################################
## ------ MARK: Cmdlet Binding ------
#####################################################################################
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [string]$Name,
    [Alias('AR')] [string]$Arguments,
    [Alias('PN')] [string[]]$ProcessNames,
    [Alias('LP')] [string]$LogPath = 'C:\Temp\Logs',
    [Alias('LN')] [string]$LogName,
    [Alias('SC')] [int[]]$SuccessCodes,
    [Alias('RC')] [int[]]$RebootCodes,
    [Alias('T')] [int]$TimeoutSeconds = 600,
    [switch]$AppV,
    [switch]$AppX,
    [Alias('CFG')] [string]$ConfigPath,
    [string]$Catalog,
    [Alias('SU')] [switch]$SkipUninstall,
    [ValidateSet('Strict','Lenient','Always')] [string]$CleanupPolicy = 'Strict'
)

#####################################################################################
## ------ MARK: Configuration ------
#####################################################################################

# Define default success codes
$DefaultSuccessCodes = @(0)

# Define default success (reboot required) codes
$DefaultRebootSuccess = @(3010)

# Define path to PS modules
$Modules = (Join-Path $PSScriptRoot 'Modules')

# Import modules
Import-Module (Join-Path $Modules 'Uninstall.Core.psm1')
Import-Module (Join-Path $Modules 'Uninstall.Engine.psm1')
Import-Module (Join-Path $Modules 'Uninstall.Cleanup.psm1')

# Define path to uninstall catalog (PS 5.1 does not accept more than two child path args)
$catalogPath = Join-Path (Join-Path $PSScriptRoot 'Config') 'Uninstall.Catalog.json'

# Load uninstall catalog
$UninstallCatalog = Get-Content $catalogPath -Raw | ConvertFrom-Json

# Snapshot global preferences so we can restore later
$oldGlobalVerbose = $global:VerbosePreference
$oldGlobalDebug   = $global:DebugPreference

# If the script was launched with -Verbose/-Debug, bridge them into global for consistent module behavior
if ($VerbosePreference -eq 'Continue') { $global:VerbosePreference = 'Continue' }
if ($DebugPreference   -eq 'Continue') { $global:DebugPreference   = 'Continue' }

#####################################################################################
## ------ MARK: Pre-Uninstall ------
#####################################################################################
function Invoke-PreUninstallActions {
    param ()
 
    # Place custom code here:
    
}

#####################################################################################
## ------ MARK: Post-Uninstall ------
#####################################################################################
function Invoke-PostUninstallActions {
    param ()

    # Place custom code here:
    
}

#####################################################################################
## ------ MARK: Main Script ------
#####################################################################################

# If -Catalog List is specified, show catalog entries and quit
if ($Catalog -and $Catalog.Trim().ToLower() -eq 'list') {
    Write-Host "=== Available Catalog Entries ===" -ForegroundColor Cyan
    foreach ($key in $UninstallCatalog.PSObject.Properties.Name) {
        $entry = $UninstallCatalog.$key
        [pscustomobject]@{
            'App Name'  = $key
            Description = $entry.Description
        }
    }
    return
}

# Load JSON config if provided
if ($ConfigPath) {
    if (Test-Path $ConfigPath) {
        try {
            Write-Log "JSON was provided. Loading ${ConfigPath}" -Level Verbose
            $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Log "Failed to parse config file ${ConfigPath}: $_" -Level Error
            exit 1
        }
    }
    else {
        Write-Log "Config file not found: $ConfigPath" -Level Error
        exit 1
    }
}

# Execute any pre-uninstall actions
Invoke-PreUninstallActions

try {
    # Build job list
    $jobs = @()

    if ($ConfigPath -and $config.Apps) {
        $jobs = $config.Apps
    }
    elseif ($Catalog -and $Catalog.Trim()) {
        $resolvedName = $Name
        if (-not $resolvedName -or [string]::IsNullOrWhiteSpace($resolvedName)) { $resolvedName = $Catalog }

        $jobs = @([pscustomobject]@{
            Name           = $resolvedName
            Catalog        = $Catalog
            TimeoutSeconds = $TimeoutSeconds
            LogPath        = $LogPath
            LogName        = $LogName
        })
    }
    elseif ($Name) {
        $jobs = @([pscustomobject]@{
            Name           = $Name
            Arguments      = $Arguments
            ProcessNames   = $ProcessNames
            SuccessCodes   = $SuccessCodes
            RebootCodes    = $RebootCodes
            TimeoutSeconds = $TimeoutSeconds
            LogPath        = $LogPath
            LogName        = $LogName
            AppV           = $AppV
            AppX           = $AppX
            Catalog        = $null
        })
    }
    else {
        throw "You must specify -Catalog, -Name, or -ConfigPath."
    }

    # Execute jobs and collect exit codes
    $results       = @()
    $effectiveJobs = @()

    foreach ($job in $jobs) {
        # Expand into one or many effective jobs
        $expandedJobs = Get-EffectiveJob -Job $job -UninstallCatalog $UninstallCatalog -DefaultTimeoutSeconds $TimeoutSeconds
        $expandedResults = @()

        # Choose a primary job to derive logging settings (first effective job)
        $primary = $expandedJobs | Select-Object -First 1
        if ($primary) {
            # Normalize logging settings
            if (-not $primary.LogName -or [string]::IsNullOrWhiteSpace($primary.LogName)) {
                $primary.LogName = $null
                $primary.LogPath = $null
            }
            elseif (-not $primary.LogPath -or [string]::IsNullOrWhiteSpace($primary.LogPath)) {
                $primary.LogPath = $LogPath
            }
        }

        # Start transcript once per app; keep it open through cleanup
        $jobLogFile = if ($primary) { Invoke-StartTranscript -Path $primary.LogPath -Name $primary.LogName -WhatIf:$WhatIfPreference } else { $null }

        try {
            $appExitCode = 0

            if (-not $SkipUninstall) {
                foreach ($effectiveJob in @($expandedJobs)) {
                    $effectiveJobs += $effectiveJob

                    # Run uninstall job
                    $exitCode = Invoke-UninstallJob -Job $effectiveJob -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
                    $exitCode = @($exitCode) | Where-Object { $_ -is [int] } | Select-Object -Last 1
                    if ($null -eq $exitCode) { $exitCode = 0 }
                    $expandedResults += $exitCode
                }

                # Resolve aggregate exit code for this app
                $appExitCode = Resolve-ExitCode -Results $expandedResults `
                                                -EffectiveJobs $expandedJobs `
                                                -SuccessCodes $SuccessCodes `
                                                -RebootCodes $RebootCodes `
                                                -DefaultSuccessCodes $DefaultSuccessCodes `
                                                -DefaultRebootSuccess $DefaultRebootSuccess
            }
            else {
                Write-Log "Skipping uninstall and running cleanup only for '$($job.Name)'.`n" -Level Host
                # Treat as success so cleanup policies like Strict still allow cleanup
                $appExitCode = 0
            }

            # Grab the cleanup definition from the first effective job with Cleanup
            $cleanupDef = ($expandedJobs | Where-Object { $_.Cleanup } | Select-Object -First 1).Cleanup

            # Decide if cleanup should run
            $shouldCleanup = $false
            switch ($CleanupPolicy) {
                'Strict'  { if ($appExitCode -eq 0 -or $appExitCode -eq 3010) { $shouldCleanup = $true } }
                'Lenient' {
                    foreach ($code in $expandedResults) {
                        $codeResult = Resolve-ExitCode -Results @($code) `
                                                       -EffectiveJobs $expandedJobs `
                                                       -SuccessCodes $SuccessCodes `
                                                       -RebootCodes $RebootCodes `
                                                       -DefaultSuccessCodes $DefaultSuccessCodes `
                                                       -DefaultRebootSuccess $DefaultRebootSuccess
                        if ($codeResult -eq 0 -or $codeResult -eq 3010) {
                            $shouldCleanup = $true
                            break
                        }
                    }
                }
                'Always'  { $shouldCleanup = $true }
            }

            # Run cleanup while transcript is still active
            if ($shouldCleanup -and $cleanupDef) {
                $cleanupCode = Invoke-Cleanup -Cleanup $cleanupDef -JobName $job.Name -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
                if ($cleanupCode -is [int]) { $results += $cleanupCode }
            }

            # Emit per-app exit code summary into the same transcript
            $results += $expandedResults
            if ($jobLogFile) {
                Write-Log "'$($job.Name)' Exit Code: $appExitCode" -Level Host
            }
        }
        catch {
            Write-Log "Fatal error during job '$($job.Name)': $($_.Exception.Message)" -Level Error
            if ($jobLogFile) { Invoke-StopTranscript }
            exit 1603
        }
        finally {
            if ($jobLogFile) { Invoke-StopTranscript }
        }
    }

    # Run any custom post-uninstall actions
    Invoke-PostUninstallActions

    $finalExitCode = Resolve-ExitCode -Results $results `
                                      -EffectiveJobs $effectiveJobs `
                                      -SuccessCodes $SuccessCodes `
                                      -RebootCodes $RebootCodes `
                                      -DefaultSuccessCodes $DefaultSuccessCodes `
                                      -DefaultRebootSuccess $DefaultRebootSuccess
    Write-Log "Script Exit Code: $finalExitCode" -Level Host
    exit $finalExitCode
}
catch {
    Write-Log "Fatal script error: $($_.Exception.Message)" -Level Error
    exit 1603
}
finally {
    # Restore global preferences
    $global:VerbosePreference = $oldGlobalVerbose
    $global:DebugPreference   = $oldGlobalDebug
}