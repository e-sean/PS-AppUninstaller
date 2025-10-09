<#
    .SYNOPSIS
    Uninstaller module for Remove-App.ps1. Provides functions that support discovery and execution of application uninstalls.

    .DESCRIPTION
    The Uninstaller module centralizes all helper functions used by Remove-App.ps1 to identify installed applications and perform removals.
    Includes functions to:
      - Enumerate HKLM and HKU uninstall registry keys
      - Resolve application DisplayName patterns to uninstall strings
      - Handle AppX and AppV package removals
      - Stop running processes prior to uninstall
      - Invoke uninstall commands with consistent logging and WhatIf support

    .NOTES
    Author: Sean Estrella
    GitHub: https://github.com/e-sean
    LinkedIn: https://www.linkedin.com/in/seanestrella/

    Version: 1.0.2
#>

#####################################################################################
## ------ Functions: MARK: Search Helpers ------
#####################################################################################

function Get-OwnerSidFromKeyPath {
    param([string]$Key)
    if ([string]::IsNullOrWhiteSpace($Key)) { return $null }
    # Expect: REGISTRY::HKEY_USERS\<SID>\Software\...
    $m = [regex]::Match($Key, 'HKEY_USERS\\([^\\]+)\\', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Get-ProfilePathForSid {
    param([Parameter(Mandatory)][string]$Sid)
    # HKLM\...\ProfileList\<SID>\ProfileImagePath usually holds the profile root
    $reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
    try {
        $p = (Get-ItemProperty -Path $reg -ErrorAction Stop).ProfileImagePath
        if ($p) { return $p }
    } catch {}
    return $null
}

function Get-HKURegKeys {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$Sids
    )

    $regKeys = @()
    foreach ($sid in $Sids) {
        foreach ($path in @(
            "REGISTRY::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "REGISTRY::HKEY_USERS\$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )) {
            $item = Get-Item $path -ErrorAction SilentlyContinue
            if ($item) { $regKeys += $item.Name }
        }
    }
    return $regKeys
}

function Get-ArpPropertyByDisplayName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    $results = @()

    Write-Log "Checking HKLM hive for matching product..." -Level Verbose
    $hklmItems = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall,
                               HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
                 Get-ItemProperty -ErrorAction SilentlyContinue |
                 Where-Object { $_.DisplayName -like $Name }

    foreach ($v in $hklmItems) {
        $results += [pscustomobject]@{
            DisplayName     = $v.DisplayName
            UninstallString = $v.UninstallString
            DisplayVersion  = $v.DisplayVersion
            InstallLocation = $v.InstallLocation
            PSPath          = $v.PSPath
            RegistryKey     = Invoke-NormalizeRegKey -Path $v.PSPath
            OwnerSid        = $null
            Hive            = 'HKLM'
        }
    }

    Write-Log "Checking HKU hives for matching product..." -Level Verbose
    $sids = Get-HKUSids
    foreach ($sid in $sids) {
        $key = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        if (Test-Path $key) {
            $values = Get-ChildItem -Path $key -ErrorAction SilentlyContinue |
                      Get-ItemProperty -ErrorAction SilentlyContinue |
                      Where-Object { $_.DisplayName -like $Name }

            foreach ($v in $values) {
                $results += [pscustomobject]@{
                    DisplayName     = $v.DisplayName
                    UninstallString = $v.UninstallString
                    DisplayVersion  = $v.DisplayVersion
                    InstallLocation = $v.InstallLocation
                    PSPath          = $v.PSPath
                    RegistryKey     = Invoke-NormalizeRegKey -Path $v.PSPath
                    OwnerSid        = $sid
                    Hive            = 'HKU'
                }
            }
        }
    }

    if (-not $results) {
        Write-Log "No matching uninstall string(s) found for '$Name'." -Level Warning
        return
    }

    return $results
}

#####################################################################################
## ------ Functions: MARK: Pre-Uninstall Helpers ------
#####################################################################################

function Stop-TargetProcess {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ProcessName,
        [switch]$Wait,
        [int]$TimeoutSeconds = 30
    )

    if ($WhatIfPreference) {
        Write-Host " [WhatIf] Would stop processes matching name: $($Job.ProcessNames -join ', ')"
    }

    foreach ($name in $ProcessName) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                $msg = "$($p.ProcessName) (PID $($p.Id))"
                if ($WhatIfPreference) {
                    Write-Host " [WhatIf] Would stop process: $msg"
                }
                elseif ($PSCmdlet.ShouldProcess($p.ProcessName, "Stop process PID $($p.Id)")) {
                    try {
                        $proc = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
                        if ($proc) {
                            Stop-Process -Id $p.id -Force -ErrorAction Stop
                            Write-Log " Stopped process: $msg"
                        }
                    }
                    catch {
                        Write-Log " Failed to stop process $($msg): $($_)" -Level Warning
                    }
                }
            }

            if ($WaitUntilClosed) {
                if ($WhatIfPreference) {
                    Write-Host " [WhatIf] Would wait up to $TimeoutSeconds seconds for $name to close."
                }
                else {
                    $elapsed = 0
                    while ((Get-Process -Name $name -ErrorAction SilentlyContinue) -and ($elapsed -lt $TimeoutSeconds)) {
                        Start-Sleep -Seconds 1
                        $elapsed++
                    }
                    if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
                        Write-Log " Process $name still running after $TimeoutSeconds seconds." -Level Warning
                    }
                    else {
                        Write-Log " Confirmed process $name is closed." -Level Host
                    }
                }
            }
        }
        else {
            Write-Log " No running process found matching '$name'."
            if ($WaitUntilClosed -and $WhatIfPreference) {
                Write-Host " [WhatIf] Would have waited up to $TimeoutSeconds seconds for $name if it were running."
            }
        }
    }
}

#####################################################################################
## ------ Functions: MARK: Security Helpers ------
#####################################################################################

function Split-QuotedTokens {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    # Matches quoted segments or non-space runs
    return [System.Text.RegularExpressions.Regex]::Matches($Text, '("([^"]|\\")*"|\S+)') | ForEach-Object { $_.Value }
}

function Test-UnsafeToken {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    # Block shell metacharacters and control chars
    return ($Text -match '[\|\&\;\<\>\^%`"\''\r\n]')
}

function Format-ExeArgument {
    param([string]$JobArguments)
    $result = @()
    if (-not $JobArguments) { return $result }

    $tokens = Split-QuotedTokens -Text $JobArguments
    foreach ($tok in $tokens) {
        $t = $tok.Trim()
        if (Test-UnsafeToken $t) { throw "Unsafe token in EXE arguments: $t" }
        # If token is quoted, strip outer quotes
        if ($t.StartsWith('"') -and $t.EndsWith('"')) {
            $t = $t.Substring(1, $t.Length - 2)
        }
        # Basic length guard
        if ($t.Length -gt 512) { throw "Token too long in EXE arguments." }
        # Allow typical switch/value shapes; final validation is character-level (no metacharacters).
        # Accept empty after stripping: ignore.
        if ($t.Trim().Length -gt 0) { $result += $t }
    }
    return $result
}

function Test-SafePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $false }
    # Reject UNC and forward-slash forms
    if ($full -match '^(\\\\|\\\\\?\\|//)') { return $false }
    # Require local drive path like C:\
    return ($full -match '^[A-Za-z]:\\')
}

function Test-ExecutableTarget {
    param(
        [string]$ExePath,
        [switch]$PermitUserAppData
    )


    if ([string]::IsNullOrWhiteSpace($ExePath)) {
        return [pscustomobject]@{ IsSafe=$false; Reason='EmptyPath' }
    }

    try { $full = [System.IO.Path]::GetFullPath($ExePath) }
    catch { return [pscustomobject]@{ IsSafe=$false; Reason='InvalidPath' } }

    $name = [System.IO.Path]::GetFileName($full).ToLowerInvariant()

    if ($name -eq 'msiexec.exe') {
        return [pscustomobject]@{ IsSafe=$true; Reason='Msiexec' }
    }

    if (-not (Test-Path $full)) {
        return [pscustomobject]@{ IsSafe=$false; Reason='NotFound'; Path=$full }
    }

    $blocked = @('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe')
    if ($blocked -contains $name) {
        return [pscustomobject]@{ IsSafe=$false; Reason='BlockedShell'; Path=$full }
    }

    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($full)
    if ($info.InternalName -and ($blocked -contains $info.InternalName.ToLowerInvariant())) {
        return [pscustomobject]@{ IsSafe=$false; Reason='BlockedInternalName'; Path=$full }
    }

    $fullLower = $full.ToLowerInvariant()
    if ($fullLower -like 'c:\program files*' -or
        $fullLower -like 'c:\program files (x86)*' -or
        $fullLower -like 'c:\windows*' -or
        $fullLower -like 'c:\programdata*' -or
        ($PermitUserAppData -and $fullLower -like 'c:\users\*\appdata\*')) {
        return [pscustomobject]@{ IsSafe=$true; Reason='SafeRoot'; Path=$full }
    }

    return [pscustomobject]@{ IsSafe=$false; Reason='OutsideSafeRoots'; Path=$full }
}


function Get-UninstallType {
    param(
        [Parameter(Mandatory)] [string]$ExePath,
        [string]$ExeArgs
    )

    $exeName = [System.IO.Path]::GetFileName($ExePath).ToLowerInvariant()

    # If the executable is msiexec.exe, it's MSI
    if ($exeName -eq 'msiexec.exe') { return 'MSI' }

    # If the target itself is an MSI file
    if ($ExePath -like '*.msi') { return 'MSI' }

    # Otherwise treat as EXE
    return 'EXE'
}

function Format-MsiArgument {
    param(
        [string]$JobArguments,   # raw extra text from job/catalog
        [string]$LogPath         # optional log path
    )

    $allowedSwitches = @('/qn','/qb','/norestart','/forcerestart','/l','/l*v')
    $result = @()

    if ($JobArguments) {
        # Split on whitespace while preserving quoted tokens
        $tokens = [System.Text.RegularExpressions.Regex]::Matches($JobArguments, '("([^"]|\\")*"|\S+)') |
                  ForEach-Object { $_.Value }

        foreach ($tok in $tokens) {
            $t = $tok.Trim()

            # Block shell metacharacters
            if (Test-UnsafeToken $t) {
                throw "Unsafe token in MSI arguments: $t"
            }

            # Whitelisted switches
            if ($allowedSwitches -contains $t.ToLowerInvariant()) {
                if ($t -like '/l*') {
                    # Logging switches require a safe path
                    if (-not (Test-SafePath $LogPath)) {
                        throw "Invalid MSI log path: $LogPath"
                    }
                    $result += $t
                    $result += $LogPath
                }
                else {
                    $result += $t
                }
            }
            # MSI properties (KEY=VALUE)
            elseif ($t -match '^[A-Z0-9_]+=') {
                $pair = $t.Split('=',2)
                $key  = $pair[0]
                $val  = $pair[1]

                if ($key -notmatch '^[A-Z0-9_]+$') {
                    throw "Invalid MSI property name: $key"
                }
                if ($val -notmatch '^[A-Za-z0-9._\-\s\\:]+$') {
                    throw "Invalid MSI property value for $key"
                }
                $result += "$key=$val"
            }
            else {
                throw "Unsupported MSI argument: $t"
            }
        }
    }

    return $result
}

#####################################################################################
## ------ Functions: MARK: Uninstall Helpers ------
#####################################################################################

function Invoke-UninstallCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [object]$Arguments,   # string or string[]
        [switch]$Wait,
        [int]$TimeoutSeconds = 0
    )

    $resolvedFilePath = Expand-EnvValue $FilePath
    if (-not (Test-ExecutableTarget -ExePath $resolvedFilePath)) {
        throw "Unsafe catalog executable target: $resolvedFilePath"
    }

    $type = Get-UninstallType -ExePath $resolvedFilePath
    Write-Log "Catalog uninstall type resolved: $type (exePath='$resolvedFilePath')" -Level Verbose

    # Normalize arguments into a safe array
    $argList = @()
    if ($Arguments -is [string]) {
        try {
            $argList = if ($type -eq 'MSI') {
                Format-MsiArgument -JobArguments $Arguments
            } else {
                Format-ExeArgument -JobArguments $Arguments
            }
        }
        catch {
            throw "Unsafe catalog arguments for ${FilePath}: $($_.Exception.Message)"
        }
    }
    elseif ($Arguments -is [System.Collections.IEnumerable] -and -not ($Arguments -is [string])) {
        foreach ($t in $Arguments) {
            if (Test-UnsafeToken ([string]$t)) {
                throw "Unsafe token in catalog arguments: $t"
            }
            $argList += [string]$t
        }
    }

    # Build preview string for logging
    $commandLinePreview = if ($resolvedFilePath -match '\s') {
        "`"$resolvedFilePath`" $($argList -join ' ')"
    } else {
        "$resolvedFilePath $($argList -join ' ')"
    }

    Write-Log " Executing catalog uninstall: $commandLinePreview" -Level Verbose

    if ($Wait) {
        $proc = Start-Process -FilePath $resolvedFilePath `
                              -ArgumentList $argList `
                              -WindowStyle Hidden `
                              -PassThru

        if ($TimeoutSeconds -gt 0) {
            if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
                try { $proc.Kill() } catch {}
                return [pscustomobject]@{
                    FilePath    = $resolvedFilePath
                    Arguments   = ($argList -join ' ')
                    CommandLine = $commandLinePreview
                    ExitCode    = 1460   # timeout
                }
            }
        }
        else {
            $proc.WaitForExit()
        }

        return [pscustomobject]@{
            FilePath    = $resolvedFilePath
            Arguments   = ($argList -join ' ')
            CommandLine = $commandLinePreview
            ExitCode    = $proc.ExitCode
        }
    }
    else {
        # Fire-and-forget mode
        Start-Process -FilePath $resolvedFilePath `
                      -ArgumentList $argList `
                      -WindowStyle Hidden | Out-Null

        return [pscustomobject]@{
            FilePath    = $resolvedFilePath
            Arguments   = ($argList -join ' ')
            CommandLine = $commandLinePreview
            ExitCode    = 0
        }
    }
}

function Invoke-UninstallString {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory)] [string]$UninstallString,
        [string]$DisplayName,
        [string]$Arguments,
        [string]$AppVersion,
        [string]$InstallLocation,
        [string]$RegistryKey,
        [int]$TimeoutSeconds,
        [string]$LogPath,
        [string]$OwnerSid,
        [string]$Hive
    )

    # Normalize MSI /I to /X
    if ($UninstallString -match '/I\s*{[0-9A-F-]+}') {
        $UninstallString = $UninstallString -replace '/I', '/X'
    }

    # Split exe path and baked args (before expansion)
    if ($UninstallString -match '^"(.+?)"\s*(.*)$') {
        $exePath = $matches[1]; $exeArgs = $matches[2]
    } elseif ($UninstallString -match '^(\S+)\s*(.*)$') {
        $exePath = $matches[1]; $exeArgs = $matches[2]
    } else {
        throw "Unexpected uninstall string format: $UninstallString"
    }

    # Expand environment variables in the exe path only
    $expandedExePath = [Environment]::ExpandEnvironmentVariables($exePath)

    # Permit AppData roots if this came from HKU
    $permitUser = ($Hive -eq 'HKU')
    $targetCheck = Test-ExecutableTarget -ExePath $expandedExePath -PermitUserAppData:$permitUser
    if (-not $targetCheck.IsSafe) {
        throw "Unsafe or missing executable from ARP UninstallString: $expandedExePath ($($targetCheck.Reason))"
    }

    $UninstallType = Get-UninstallType -ExePath $expandedExePath -ExeArgs $exeArgs
    Write-Log "Uninstall type resolved: $UninstallType (exePath='$expandedExePath')" -Level Verbose

    $finalArgsString = $exeArgs
    $extraArgsArray  = @()

    try {
        if ($UninstallType -eq 'MSI') {
            # Strict MSI sanitizer
            $extraArgsArray = Format-MsiArgument -JobArguments $Arguments -LogPath $LogPath
        }
        else {
            # EXE sanitizer: allows flags like --force-uninstall
            $extraArgsArray = Format-ExeArgument -JobArguments $Arguments
        }
    }
    catch {
        throw "Unsafe argument detected for ${DisplayName}: $($_.Exception.Message)"
    }

    $commandLinePreview = if ($expandedExePath -match '\s') {
        "`"$expandedExePath`" $finalArgsString $($extraArgsArray -join ' ')"
    } else {
        "$expandedExePath $finalArgsString $($extraArgsArray -join ' ')"
    }

    Write-Host "  DisplayName : $DisplayName"
    Write-Host "  RegistryKey : $RegistryKey"
    Write-Host "  Version     : $AppVersion"
    Write-Host "  Location    : $InstallLocation"
    Write-Host "  FilePath    : $expandedExePath"
    Write-Host "  Type        : $UninstallType"
    Write-Host "  Base Args   : $finalArgsString"
    if ($extraArgsArray.Count -gt 0) { Write-Host "  Extra Args  : $($extraArgsArray -join ' ')" }
    Write-Host "  CommandLine : $commandLinePreview"

    if ($PSCmdlet.ShouldProcess($DisplayName, "Uninstall")) {
        if ($WhatIfPreference) {
            Write-Host " [WhatIf] Would execute: $commandLinePreview"
            return [PSCustomObject]@{
                DisplayName = $DisplayName
                FilePath    = $expandedExePath
                Arguments   = "$finalArgsString $($extraArgsArray -join ' ')"
                CommandLine = $commandLinePreview
                ExitCode    = 0
            }
        }
        else {
            $argList = @()
            if ($finalArgsString -and $finalArgsString.Trim().Length -gt 0) {
                $argList += $finalArgsString
            }
            $argList += $extraArgsArray

            $proc = Start-Process -FilePath $expandedExePath -ArgumentList $argList -WindowStyle Hidden -PassThru -Wait
            Write-Log " Executed: $commandLinePreview"
            return [PSCustomObject]@{
                DisplayName = $DisplayName
                FilePath    = $expandedExePath
                Arguments   = "$finalArgsString $($extraArgsArray -join ' ')"
                CommandLine = $commandLinePreview
                ExitCode    = $proc.ExitCode
            }
        }
    }
}

function Invoke-AppXRemoval {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    Write-Log "=== Checking AppX/MSIX packages for pattern '$Name' ==="
    $exitCode = 0

    try {
        $packages = @( Get-AppxPackage -Name $Name -AllUsers -ErrorAction SilentlyContinue )
        if ($packages) {
            foreach ($pkg in $packages) {
                Write-Host "  DisplayName     : $($pkg.Name)"
                Write-Host "  PackageFullName : $($pkg.PackageFullName)"

                foreach ($u in $pkg.PackageUserInformation) {
                    Write-Host "  UserSID      : $($u.UserSecurityId.Sid)"
                    Write-Host "  Username     : $($u.UserSecurityId.Username)"
                    Write-Host "  InstallState : $($u.InstallState)"
                }
 
                $cmd = "Remove-AppxPackage -Package `"$($pkg.PackageFullName)`" -AllUsers -Confirm:`$false -ErrorAction Stop"
                if ($WhatIfPreference) {
                    Write-Host " [WhatIf] Would execute: $cmd"
                }
                elseif ($PSCmdlet.ShouldProcess($pkg.Name, "Remove AppX package for all users")) {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -Confirm:$false -ErrorAction Stop
                    Write-Log " Executed: $cmd"
                }
            }
        }

        $prov = @( Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Name )
        if ($prov) {
            foreach ($p in $prov) {
                Write-Host "  Provisioned DisplayName : $($p.DisplayName)"
                Write-Host "  PackageName             : $($p.PackageName)"
                Write-Host "  (Provisioned package - applies to all new users, no per-user SID info)"

                $cmd = "Remove-AppxProvisionedPackage -Online -PackageName `"$($p.PackageName)`" -Confirm:`$false -ErrorAction Stop"
                if ($WhatIfPreference) {
                    Write-Host " [WhatIf] Would execute: $cmd"
                }
                elseif ($PSCmdlet.ShouldProcess($p.DisplayName, "Remove provisioned AppX package")) {
                    Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -Confirm:$false -ErrorAction Stop
                    Write-Log " Executed: $cmd"
                }
            }
        }

        if (-not $packages -and -not $prov) {
            Write-Log "No AppX packages found matching '$Name'." -Level Warning
        }
    }
    catch {
        Write-Log "AppX removal failed: $_" -Level Error
        $exitCode = 1603
    }

    Write-Log "=== Finished AppX/MSIX removal for '$Name' ==="
    return $exitCode
}

function Invoke-AppVRemoval {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory)]
        [string]$Name
    )

    # Import AppvClient PS module
    if (-not (Get-Command Get-AppvClientPackage -ErrorAction SilentlyContinue)) {
        try {
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                Import-Module AppvClient -UseWindowsPowerShell -ErrorAction Stop
            } else {
                Import-Module AppvClient -ErrorAction Stop
            }
        }
        catch {
            Write-Log "Unable to import AppvClient module. Validate that the App-V client feature is installed and enabled." -Level Error
            return 9009
        }
        
        if (-not (Get-Command Get-AppvClientPackage -ErrorAction SilentlyContinue)) {
            Write-Log "App-V cmdlets not available after import." -Level Error
            return 9009
        }
    }


    Write-Log "=== Checking App-V packages for pattern '$Name' ==="
    $exitCode = 0

    try {
        $pkg = Get-AppvClientPackage -Name $Name -ErrorAction SilentlyContinue
        if ($pkg) {
            Write-Host "  DisplayName : $($pkg.Name)"
            Write-Host "  PackageId   : $($pkg.PackageId)"
            Write-Host "  VersionId   : $($pkg.VersionId)"

            if ($PSCmdlet.ShouldProcess($pkg.Name, "Remove App-V package")) {
                Remove-AppvClientPackage -PackageId $pkg.PackageId -VersionId $pkg.VersionId -Confirm:$false -ErrorAction Stop
                Write-Log "  Removed App-V package: $($pkg.Name)"
                $exitCode = 0
            }
            else {
                if ($WhatIfPreference) {
                    Write-Host "  [WhatIf] Would remove App-V package: $($pkg.Name) ($($pkg.PackageId)/$($pkg.VersionId))"
                }
                $exitCode = 0
            }
        }
        else {
            Write-Log "No App-V package found matching '$Name'." -Level Warning
            $exitCode = 1605
        }
    }
    catch {
        Write-Log "App-V removal failed: $_" -Level Error
        $exitCode = 1603
    }

    Write-Log "=== Finished App-V removal for '$Name' ==="
    return $exitCode
}



#####################################################################################
## ------ Functions: MARK: Orchestrator ------
#####################################################################################

function Invoke-UninstallJob {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [pscustomobject]$Job
    )

    Write-Log "=== Starting uninstall job for $($Job.Name) ==="

    $exitCode = 0
    try {
        if ($Job.ProcessNames) {
            Stop-TargetProcess -ProcessName $Job.ProcessNames -Wait -TimeoutSeconds 30 -WhatIf:$WhatIfPreference
        }

        if ($Job.AppX) {
            if ($WhatIfPreference) { Write-Host " [WhatIf] Would attempt AppX removal for $($Job.Name)" }
            $exitCode = Invoke-AppXRemoval -Name $Job.Name -WhatIf:$WhatIfPreference
        }
        elseif ($Job.Catalog -and $Job.Catalog.Trim()) {
            Write-Host " Using catalog entry: $($Job.Catalog)"
            Write-Host " FilePath           : $($Job.FilePath)"
            Write-Host " Arguments          : $($Job.Arguments)"

            $argsToRun = $Job.Arguments
            if ($argsToRun -is [string]) {
                try {
                    # Determine uninstall type from the catalog exe path
                    $type = Get-UninstallType -ExePath $Job.FilePath
                    Write-Log "Catalog uninstall type resolved: $type (exePath='$($Job.FilePath)')" -Level Verbose

                    if ($type -eq 'MSI') {
                        $argsToRun = Format-MsiArgument -JobArguments $argsToRun
                    }
                    else {
                        $argsToRun = Format-ExeArgument -JobArguments $argsToRun
                    }
                }
                catch {
                    throw "Unsafe catalog arguments for $($Job.FilePath): $($_.Exception.Message)"
                }
            }

            if ($PSCmdlet.ShouldProcess($Job.Name, "Catalog uninstall")) {
                if ($WhatIfPreference) {
                    Write-Host " [WhatIf] Would execute: $($Job.FilePath) $((@($argsToRun) -join ' '))"
                    $exitCode = 0
                }
                else {
                    $result = Invoke-UninstallCommand -FilePath $Job.FilePath `
                                                     -Arguments $argsToRun `
                                                     -Wait:$true `
                                                     -TimeoutSeconds $Job.TimeoutSeconds
                    $exitCode = $result.ExitCode
                }
            }
        }
        else {
            # Default: ARP uninstall
            $searchResults = Get-ArpPropertyByDisplayName -Name $Job.Name
            if ($searchResults) {
                $searchResults = @($searchResults)
                Write-Host "`n Found $($searchResults.Count) match(es) for pattern '$($Job.Name)':"
                $i = 1
                foreach ($m in $searchResults) {
                    Write-Host " [$i] $($m.DisplayName)"
                    $i++
                }

                $target = $searchResults | Select-Object -First 1
                if ($searchResults.Count -gt 1) {
                    Write-Log "Multiple matches found. Only the first match will be uninstalled.`nTo uninstall more than one app, use -ConfigPath parameter with a json file." -Level Warning
                }

                Write-Host "`nUsing match: $($target.DisplayName)"

                $result = Invoke-UninstallString -UninstallString $target.UninstallString `
                                                 -DisplayName $target.DisplayName `
                                                 -Arguments $Job.Arguments `
                                                 -AppVersion $target.DisplayVersion `
                                                 -InstallLocation $target.InstallLocation `
                                                 -RegistryKey (Invoke-NormalizeRegKey -Path $target.PSPath) `
                                                 -TimeoutSeconds $Job.TimeoutSeconds `
                                                 -OwnerSid $target.OwnerSid `
                                                 -Hive $target.Hive `
                                                 -WhatIf:$WhatIfPreference
                if ($result) {
                    Write-Log " Exit Code: $($result.ExitCode)"
                    $exitCode = $result.ExitCode
                }
            }
            else {
                Write-Log "Could not find '$($Job.Name)'." -Level Warning
            }
        }
    }
    catch {
        Write-Log "Fatal: Uninstall job for $($Job.Name) aborted due to unsafe input or error: $($_.Exception.Message)" -Level Error
        $exitCode = 1603
        Write-Log "=== Aborted uninstall job for $($Job.Name) ===`n"
        return $exitCode
    }

    Write-Log "=== Finished uninstall job for $($Job.Name) ===`n"
    return $exitCode
}

Export-ModuleMember -Function `
    Get-ArpPropertyByDisplayName, `
    Stop-TargetProcess, `
    Invoke-NormalizeRegKey, `
    Split-QuotedTokens, `
    Test-UnsafeToken, `
    Format-MsiArgument, `
    Test-SafePath, `
    Test-ExecutableTarget, `
    Get-UninstallType, `
    Format-MsiArgument, `
    Invoke-UninstallCommand, `
    Invoke-UninstallString, `
    Invoke-AppXRemoval, `
    Invoke-AppVRemoval, `
    Invoke-UninstallJob