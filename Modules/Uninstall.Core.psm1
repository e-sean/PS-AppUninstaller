function Get-EffectiveJob {
    param(
        [pscustomobject]$Job,
        [pscustomobject]$UninstallCatalog,
        [int]$DefaultTimeoutSeconds
    )

    function New-BaseJob {
        param($Name,$FilePath,$Arguments,$TimeoutSeconds,$ProcessNames,
              $SuccessCodes,$RebootCodes,$AppV,$AppX,$Cleanup,$Catalog,$LogPath,$LogName)

        return [pscustomobject]@{
            Name           = $Name
            FilePath       = $FilePath
            Arguments      = $Arguments
            TimeoutSeconds = $TimeoutSeconds
            ProcessNames   = $ProcessNames
            SuccessCodes   = $SuccessCodes
            RebootCodes    = $RebootCodes
            AppV           = $AppV
            AppX           = $AppX
            Cleanup        = $Cleanup
            Catalog        = $Catalog
            LogPath        = $LogPath
            LogName        = $LogName
        }
    }

    $jobs = @()

    if ($Job.Catalog -and $Job.Catalog.Trim()) {
        $CatalogDefinition = $UninstallCatalog.$($Job.Catalog)
        if (-not $CatalogDefinition) {
            throw "Catalog key '$($Job.Catalog)' not found in Uninstall.Catalog.json."
        }

        $resolvedName = if ($Job.Name) { $Job.Name } else { $Job.Catalog }

        $base = New-BaseJob `
            -Name $resolvedName `
            -FilePath $CatalogDefinition.FilePath `
            -Arguments $CatalogDefinition.Arguments `
            -TimeoutSeconds (Get-EffectiveValue $Job.TimeoutSeconds $CatalogDefinition.TimeoutSeconds $DefaultTimeoutSeconds) `
            -ProcessNames $CatalogDefinition.ProcessNames `
            -SuccessCodes $CatalogDefinition.SuccessCodes `
            -RebootCodes $CatalogDefinition.RebootCodes `
            -AppV $CatalogDefinition.AppV `
            -AppX $CatalogDefinition.AppX `
            -Cleanup $CatalogDefinition.Cleanup `
            -Catalog $Job.Catalog `
            -LogPath $Job.LogPath `
            -LogName $Job.LogName
    }
    else {
        $base = New-BaseJob `
            -Name $Job.Name `
            -FilePath $Job.FilePath `
            -Arguments $Job.Arguments `
            -TimeoutSeconds (Get-EffectiveValue $Job.TimeoutSeconds $null $DefaultTimeoutSeconds) `
            -ProcessNames $Job.ProcessNames `
            -SuccessCodes $Job.SuccessCodes `
            -RebootCodes $Job.RebootCodes `
            -AppV $Job.AppV `
            -AppX $Job.AppX `
            -Cleanup $Job.Cleanup `
            -Catalog $null `
            -LogPath $Job.LogPath `
            -LogName $Job.LogName
    }

    $rawPath = $base.FilePath
    if ($rawPath -match '^%APPDATA%\\' -or $rawPath -match '^%LOCALAPPDATA%\\') {
        $subPath = if ($rawPath -match '^%APPDATA%\\') {
            $rawPath -replace '^%APPDATA%\\','AppData\Roaming\'
        } else {
            $rawPath -replace '^%LOCALAPPDATA%\\','AppData\Local\'
        }

        foreach ($userProfile in Get-UserProfilePaths) {
            $jobCopy = $base.PSObject.Copy()
            $jobCopy.FilePath = Join-Path $userProfile $subPath
            $jobs += $jobCopy
        }
    }
    else {
        $jobCopy = $base.PSObject.Copy()
        $jobCopy.FilePath = Expand-EnvValue $rawPath
        $jobs += $jobCopy
    }

    # Wildcard expansion
    $final = @()
    foreach ($j in $jobs) {
        $fp = [string]$j.FilePath

        if ($fp -match '\\\*\\') {
            $targets = Resolve-WildcardTargets -Path $fp

            if ($targets) {
                foreach ($t in $targets) {
                    $jc = $j.PSObject.Copy()
                    $jc.FilePath = $t
                    $final += $jc
                }
                Write-Log ("Expanded wildcard path into {0} job(s)." -f $targets.Count) -Level Verbose
            }
            else {
                Write-Log "Uninstall path not found: '$($j.Name)': $fp" -Level Warning
            }
        }
        else {
            $final += $j
        }
    }

    # ----- Validation -----
    $validated = @()
    foreach ($job in $final) {
        if ($job.Catalog) {
            # Catalog jobs: validate FilePath now
            if (-not (Test-Path -LiteralPath $job.FilePath)) {
                Write-Log "Uninstall target not found for catalog job '$($job.Name)': $($job.FilePath)" -Level Warning
                continue
            }
        }
        else {
            # Name-driven jobs: do NOT validate FilePath here
            # FilePath may be null or irrelevant; ARP uninstall string will be parsed later
            if (-not $job.FilePath) {
                Write-Log "No FilePath for name-driven job '$($job.Name)'. Will attempt to resolve UninstallString later." -Level Verbose
            }
            else {
                Write-Log "Ignoring provided FilePath for name-driven job '$($job.Name)': $($job.FilePath)" -Level Verbose
            }
        }
        $validated += $job
    }

    return $validated
}

function Resolve-WildcardTargets {
    [CmdletBinding()]
    param([string]$Path)

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)

    $marker = '\*\'
    $idx = $expanded.IndexOf($marker)
    if ($idx -lt 0) { return @($expanded) }

    $base = $expanded.Substring(0, $idx)
    $tail = $expanded.Substring($idx + $marker.Length)

    if (-not (Test-Path -LiteralPath $base -PathType Container)) {
        Write-Log "Base directory does not exist: $base" -Level Verbose
        return @()
    }

    $m = @()
    Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $candidate = Join-Path $_.FullName $tail
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            # Only add if the final file actually exists
            $m += $candidate
        }
    }
    return $m
}

function Get-UserProfilePaths {
    [CmdletBinding()]
    param()

    # Enumerate real user profiles under C:\Users
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -notin @('Public','Default','Default User','All Users') -and
            ($_ | Get-ItemProperty -ErrorAction SilentlyContinue)
        } |
        Select-Object -ExpandProperty FullName
}

function Invoke-NormalizeRegKey {
    param([string]$Path)

    if (-not $Path) { return $null }

    # Remove the provider prefix if present
    $normalized = $Path -replace '^Microsoft\.PowerShell\.Core\\Registry::',''

    # Normalize hive names to HKLM/HKCU
    $normalized = $normalized -replace '^HKEY_LOCAL_MACHINE','HKLM'
    $normalized = $normalized -replace '^HKEY_CURRENT_USER','HKCU'

    return $normalized
}

function Get-HKUSids {
    [CmdletBinding()]
    param()
    (Get-ChildItem REGISTRY::HKEY_USERS -ErrorAction SilentlyContinue).PSChildName |
        Where-Object {
            ($_ -notlike '*_Classes*' -and
             $_ -notlike '.DEFAULT'   -and
             $_ -ne 'S-1-5-18'        -and
             $_ -ne 'S-1-5-19'        -and
             $_ -ne 'S-1-5-20')
        }
}

function Expand-EnvValue {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,

        [switch]$AllUsers
    )
    process {
        if ($null -eq $InputObject) { return $InputObject }

        $expandOne = {
            param($val)

            if ($AllUsers) {
                switch -Regex ($val) {
                    '^%APPDATA%\\' {
                        $subPath = $val -replace '^%APPDATA%\\','AppData\Roaming\'
                        foreach ($userProfile in Get-UserProfilePaths) {
                            Join-Path $userProfile $subPath
                        }
                        return
                    }
                    '^%LOCALAPPDATA%\\' {
                        $subPath = $val -replace '^%LOCALAPPDATA%\\','AppData\Local\'
                        foreach ($userProfile in Get-UserProfilePaths) {
                            Join-Path $userProfile $subPath
                        }
                        return
                    }
                }
            }

            # Default: single expansion
            [Environment]::ExpandEnvironmentVariables([string]$val)
        }

        if ($InputObject -is [array]) {
            $out = foreach ($v in $InputObject) { & $expandOne $v }
            return $out | ForEach-Object { $_ -replace '\\{2,}', '\' }
        }
        else {
            $out = & $expandOne $InputObject
            return $out | ForEach-Object { $_ -replace '\\{2,}', '\' }
        }
    }
}

function Get-EffectiveValue {
    param($JobValue, $CatalogValue, $DefaultValue)
    if ($null -ne $JobValue -and ($JobValue -isnot [string] -or -not [string]::IsNullOrWhiteSpace($JobValue))) { return $JobValue }
    if ($null -ne $CatalogValue -and ($CatalogValue -isnot [string] -or -not [string]::IsNullOrWhiteSpace($CatalogValue))) { return $CatalogValue }
    return $DefaultValue
}

function Get-EffectiveCodes {
    param(
        [int[]]$PipelineCodes,
        [pscustomobject[]]$Jobs,
        [string]$PropertyName,
        [int[]]$DefaultCodes
    )
    $combined = @()
    if ($PipelineCodes) { $combined += $PipelineCodes }
    foreach ($j in $Jobs) {
        $prop = $j.$PropertyName
        if ($prop) { $combined += $prop }
    }
    ($DefaultCodes + $combined) | Sort-Object -Unique
}

function Resolve-ExitCode {
    [CmdletBinding()]
    param(
        [int[]]$Results,
        [object[]]$EffectiveJobs,
        [int[]]$SuccessCodes,
        [int[]]$RebootCodes,
        [int[]]$DefaultSuccessCodes,
        [int[]]$DefaultRebootSuccess
    )

    # Normalize results into an array
    $allCodes = @($Results)

    # Build effective sets
    $effectiveAllow  = Get-EffectiveCodes $SuccessCodes $EffectiveJobs 'SuccessCodes' $DefaultSuccessCodes
    $effectiveReboot = Get-EffectiveCodes $RebootCodes  $EffectiveJobs 'RebootCodes'  $DefaultRebootSuccess

    # Map any reboot-success code to canonical 3010
    $normalizedCodes = foreach ($code in $allCodes) {
        if ($code -in $effectiveReboot) { 3010 } else { $code }
    }

    # Any codes not in the allow-list?
    $nonAllowed = $normalizedCodes | Where-Object { ($_ -notin $effectiveAllow) -and ($_ -ne 3010) }

    if ($nonAllowed) {
        # Return the highest non-allowed code
        return ($nonAllowed | Measure-Object -Maximum).Maximum
    }
    elseif ($normalizedCodes -contains 3010) {
        # Success, reboot required
        return 3010
    }
    else {
        # Success, no reboot required
        return 0
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Host','Verbose','Warning','Error','Information','Debug')]
        [string]$Level = 'Host',

        [System.ConsoleColor]$ForegroundColor,
        [System.ConsoleColor]$BackgroundColor
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = "[$stamp] $Message"

    switch ($Level) {
        'Host' {
            Write-Host $line @(
                if ($PSBoundParameters.ContainsKey('ForegroundColor')) { @{ForegroundColor=$ForegroundColor} }
                if ($PSBoundParameters.ContainsKey('BackgroundColor')) { @{BackgroundColor=$BackgroundColor} }
            )
        }
        'Verbose' {
            # Honor top-level -Verbose via global bridge
            if ($global:VerbosePreference -eq 'Continue') {
                Write-Host $line -ForegroundColor DarkGray
            }
        }
        'Warning'     { Write-Warning $line }
        'Error'       { Write-Error $line }
        'Information' { Write-Information $line }
        'Debug' {
            # Honor top-level -Debug via global bridge
            if ($global:DebugPreference -eq 'Continue') {
                Write-Host $line -ForegroundColor Magenta
            }
        }
    }
}

function Invoke-StartTranscript {
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Name,
        [switch]$WhatIf
    )

    if ($WhatIf) {
        Write-Log "Skipping transcript start due to -WhatIf." -Level Verbose
        return $null
    }

    if (-not $Path -or -not $Name) { return $null }

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
        $baseName       = [System.IO.Path]::GetFileNameWithoutExtension($Name)
        $normalizedName = "$baseName.log"
        $logFile        = Join-Path $Path $normalizedName
        Start-Transcript -Path $logFile -Append -ErrorAction Stop
        Write-Log "Transcript started: $logFile" -Level Verbose
        return $logFile
    }
    catch {
        Write-Log "Failed to start transcript at $Path\$Name. $_" -Level Warning
        return $null
    }
}

function Invoke-StopTranscript {
    try {
        Stop-Transcript | Out-Null
        Write-Log "Transcript stopped." -Level Verbose
    }
    catch {
        Write-Log "Failed to stop transcript. $_" -Level Warning
    }
}

Export-ModuleMember -Function *