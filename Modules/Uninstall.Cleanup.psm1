
#####################################################################################
## ------ Functions: MARK: Search Helpers ------
#####################################################################################

function Search-Shortcut {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string[]]$Extensions,
        [string]$Scope
    )

    if (-not (Test-Path $Path)) { return @() }

    $results = @()
    foreach ($ext in $Extensions) {
        $pattern = "$Name$ext"
        Write-Log "Search-Shortcut: Path='$Path' Pattern='$pattern' Scope='$Scope'" -Level Verbose

        $results += Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like $pattern } |
            ForEach-Object {
                [pscustomobject]@{
                    Name      = $_.Name
                    FullPath  = $_.FullName
                    Extension = $_.Extension
                    Scope     = $Scope
                }
            }
    }
    return $results
}

function Get-ShortcutPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [switch]$Lnk,
        [switch]$Url,
        [switch]$StartMenu,
        [switch]$Desktop,
        [switch]$Documents
    )

    $extensions = @()
    if ($Lnk) { $extensions += '.lnk' }
    if ($Url) { $extensions += '.url' }
    if (-not $extensions) { return @() }

    $results = @()

    # Always search all-users Start Menu
    $results += Search-Shortcut -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" -Name $Name -Extensions $extensions -Scope 'AllUsersStartMenu'

    # Public folders
    if ($Desktop)   { $results += Search-Shortcut -Path "$env:SystemDrive\Users\Public\Desktop" -Name $Name -Extensions $extensions -Scope 'PublicDesktop' }
    if ($Documents) { $results += Search-Shortcut -Path "$env:SystemDrive\Users\Public\Documents" -Name $Name -Extensions $extensions -Scope 'PublicDocuments' }

    # User profile paths (SYSTEM context: iterate all real profiles)
    if ($StartMenu -or $Desktop -or $Documents) {
        $users = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

        foreach ($u in $users) {
            $userProfile = $u.FullName

            if ($StartMenu) {
                $results += Search-Shortcut -Path "$userProfile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" -Name $Name -Extensions $extensions -Scope 'UserStartMenu'
            }
            if ($Desktop) {
                $results += Search-Shortcut -Path "$userProfile\Desktop" -Name $Name -Extensions $extensions -Scope 'UserDesktop'
                $results += Search-Shortcut -Path "$userProfile\OneDrive\Desktop" -Name $Name -Extensions $extensions -Scope 'UserDesktop'
            }
            if ($Documents) {
                $results += Search-Shortcut -Path "$userProfile\Documents" -Name $Name -Extensions $extensions -Scope 'UserDocuments'
                $results += Search-Shortcut -Path "$userProfile\OneDrive\Documents" -Name $Name -Extensions $extensions -Scope 'UserDocuments'
            }
        }
    }

    $logMsg = "Get-ShortcutPath: Name='{0}' Extensions={1} StartMenu={2} Desktop={3} Documents={4}" -f `
        $Name, ($extensions -join ', '), $StartMenu, $Desktop, $Documents

    Write-Log -Message $logMsg -Level Verbose

    return $results
}

#####################################################################################
## ------ Functions: MARK: Shortcuts ------
#####################################################################################
function Remove-Shortcut {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [string]$Name,
        [switch]$Lnk,
        [switch]$Url,
        [switch]$StartMenu,
        [switch]$Desktop,
        [switch]$Documents,
        [switch]$RemoveAll,
        [switch]$Test
    )

    try {
        # If Name is empty/missing, take no action and return success
        if ([string]::IsNullOrWhiteSpace($Name)) {
            Write-Log "Remove-Shortcut: Name is empty; skipping shortcut cleanup." -Level Verbose
            return [pscustomobject]@{ ExitCode = 0; Shortcuts = @() }
        }

        $shortcuts = @()

        if ($RemoveAll) {
            $StartMenu = $true; $Desktop = $true; $Documents = $true
        }

        $shortcuts += Get-ShortcutPath -Name $Name `
                                       -Lnk:([bool]$Lnk) `
                                       -Url:([bool]$Url) `
                                       -StartMenu:([bool]$StartMenu) `
                                       -Desktop:([bool]$Desktop) `
                                       -Documents:([bool]$Documents)

        if (-not $shortcuts) {
            Write-Log "No shortcut(s) found." -Level Host
            return [pscustomobject]@{ ExitCode = 0; Shortcuts = @() }
        }

        $removed = @()
        foreach ($sc in $shortcuts) {
            if ($Test -or $WhatIfPreference) {
                Write-Host "`n[WhatIf] Would remove shortcut: $($sc.FullPath)"
                if ($PSCmdlet.ShouldProcess($sc.FullPath, "Remove shortcut")) {
                    $removed += $sc
                }
            }
            else {
                if ($PSCmdlet.ShouldProcess($sc.FullPath, "Remove shortcut")) {
                    Write-Log "Deleting shortcut: $($sc.FullPath)" -Level Host
                    Remove-Item -Path $sc.FullPath -Force -ErrorAction SilentlyContinue
                    $removed += $sc
                }
            }
        }

        return [pscustomobject]@{
            ExitCode  = 0
            Shortcuts = $removed.FullPath
        }
    }
    catch {
        Write-Log "Shortcut removal failed: $_" -Level Error
        return [pscustomobject]@{ ExitCode = 1603; Shortcuts = @() }
    }
}

#####################################################################################
## ------ Functions: MARK: Registry Keys ------
#####################################################################################
function Remove-RegistryKeys {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Keys)

    $removed  = @()
    $exitCode = 0

    foreach ($key in $Keys) {
        # Normalize hive names and strip any trailing colon
        $normalized = $key `
            -replace '^HKEY_LOCAL_MACHINE','HKLM' `
            -replace '^HKEY_CURRENT_USER','HKCU' `
            -replace '^HKEY_CLASSES_ROOT','HKCR' `
            -replace '^HKEY_USERS','HKU' `
            -replace '^HKEY_CURRENT_CONFIG','HKCC' `
            -replace '^HKLM:','HKLM' `
            -replace '^HKCU:','HKCU' `
            -replace '^HKCR:','HKCR' `
            -replace '^HKU:','HKU' `
            -replace '^HKCC:','HKCC'

        Write-Log "Remove-RegistryKeys: Input='$key' Normalized='$normalized'" -Level Verbose

        if ($normalized -like 'HKCU\*') {
            # Expand HKCU to all user hives
            $subPath = $normalized.Substring(5) # strip 'HKCU\'
            foreach ($sid in Get-HKUSids) {
                $fullPath = "HKU:\$sid\$subPath"
                Write-Log "Expanding HKCU for SID=$sid -> $fullPath" -Level Verbose

                if (Test-Path $fullPath) {
                    if ($PSCmdlet.ShouldProcess($fullPath, "Remove registry key")) {
                        try {
                            Write-Log "Attempting to remove per-user key: $fullPath" -Level Verbose
                            Remove-Item -Path $fullPath -Recurse -Force -ErrorAction Stop
                            Write-Log "Removed per-user key: $fullPath" -Level Host
                            $removed += $fullPath
                        }
                        catch {
                            Write-Log "Failed to remove ${fullPath}: $_" -Level Warning
                            $exitCode = 1603
                        }
                    }
                }
                else {
                    Write-Log "Registry key not found: $fullPath" -Level Verbose
                }
            }
        }
        else {
            $regPath = "Registry::$normalized"
            if ($PSCmdlet.ShouldProcess($normalized, "Remove registry key")) {
                if (-not (Test-Path $regPath)) {
                    Write-Log "Registry key not found: $normalized" -Level Verbose
                    continue
                }
                try {
                    Write-Log "Attempting to remove registry key: $normalized" -Level Verbose
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed registry key: $normalized" -Level Host
                    $removed += $normalized
                }
                catch {
                    Write-Log "Failed to remove ${normalized}: $_" -Level Warning
                    $exitCode = 1603
                }
            }
        }
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Keys     = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: Filepaths ------
#####################################################################################
function Enable-Privilege {
    param([string]$Privilege)

    $definition = @"
using System;
using System.Runtime.InteropServices;

public class AdjPriv {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
        ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }

    public static bool EnablePrivilege(string privilege) {
        IntPtr htok = IntPtr.Zero;
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok)) return false;
        TokPriv1Luid tp;
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;
        if (!LookupPrivilegeValue(null, privilege, ref tp.Luid)) return false;
        if (!AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
        return true;
    }
}
"@
    Add-Type $definition -ErrorAction SilentlyContinue | Out-Null
    [AdjPriv]::EnablePrivilege($Privilege) | Out-Null
}

function Reset-Acl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target
    )

    try {
        if (-not (Test-Path -LiteralPath $Target)) {
            Write-Log "Reset-Acl: Path not found: $Target" -Level Verbose
            return $false
        }

        $item  = Get-Item -LiteralPath $Target -ErrorAction Stop
        $isDir = $item.PSIsContainer

        Write-Log "Reset-Acl: Starting ACL reset on $Target (Directory=$isDir)" -Level Verbose

        # Clear ReadOnly attribute if present
        if ($item.Attributes -band [IO.FileAttributes]::ReadOnly) {
            $item.Attributes = ($item.Attributes -bxor [IO.FileAttributes]::ReadOnly)
            Write-Log "Cleared ReadOnly attribute on: $Target" -Level Verbose
        }

        $acl = Get-Acl -LiteralPath $Target -ErrorAction Stop

        # Take ownership
        $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $acl.SetOwner([System.Security.Principal.NTAccount]$current)
        Write-Log "Set owner to $current on: $Target" -Level Verbose

        # Remove Deny ACEs
        $denyRules = @($acl.Access) | Where-Object { $_.AccessControlType -eq 'Deny' }
        foreach ($rule in $denyRules) {
            $null = $acl.RemoveAccessRuleSpecific($rule)
            Write-Log "Removed Deny ACE: $($rule.IdentityReference.Value) ($($rule.FileSystemRights)) on $Target" -Level Verbose
        }

        # Add Allow FullControl for current identity only
        if ($isDir) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $current,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
        else {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $current,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
        $acl.SetAccessRule($rule)
        Write-Log "Added Allow FullControl for '$current' on $Target" -Level Verbose

        Set-Acl -LiteralPath $Target -AclObject $acl -ErrorAction Stop
        Write-Log "Applied updated ACL to: $Target" -Level Verbose

        return $true
    }
    catch {
        Write-Log "Reset-Acl failed on ${Target}: $($_.Exception.Message)" -Level Verbose
        return $false
    }
}

function Repair-FilePermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Log "Repair-FilePermissions: Path not found: $Path" -Level Verbose
            return $false
        }

        Write-Log "Repair-FilePermissions: Enabling SeTakeOwnershipPrivilege" -Level Verbose
        Enable-Privilege SeTakeOwnershipPrivilege | Out-Null

        $item  = Get-Item -LiteralPath $Path -ErrorAction Stop
        $isDir = $item.PSIsContainer

        Write-Log "Repair-FilePermissions: Resetting ACLs on root $Path" -Level Verbose
        $rootAclResult = Reset-Acl -Target $Path

        $total  = 0
        $failed = 0

        if ($isDir) {
            Write-Log "Repair-FilePermissions: Enumerating children under $Path" -Level Verbose
            Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $total++
                if (-not (Reset-Acl -Target $_.FullName)) {
                    $failed++
                }
            }
            Write-Log "Repair-FilePermissions: Processed $total child item(s); $failed failed" -Level Verbose
        }

        if ($rootAclResult) {
            Write-Log "Successfully reset permissions on: $Path" -Level Host
            if ($failed -gt 0) {
                Write-Log "Repair-FilePermissions: $failed child item(s) could not be remediated under $Path" -Level Verbose
            }
            return $true
        }
        else {
            Write-Log "Repair-FilePermissions: Root remediation failed on $Path" -Level Verbose
            return $false
        }
    }
    catch {
        Write-Log "Repair-FilePermissions fatal error on ${Path}: $($_.Exception.Message)" -Level Verbose
        return $false
    }
}

function Remove-FilePaths {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Paths)

    $removed  = @()
    $exitCode = 0

    foreach ($raw in $Paths) {
        Write-Log "Remove-FilePaths: Input='$raw'" -Level Verbose

        if ($raw -like 'env:\*' -or $raw -match '%\w+%') {
            Write-Log "Expanding environment/catalog path '$raw' for all users..." -Level Verbose
        }

        $expandedPaths = Expand-EnvValue -AllUsers $raw
        Write-Log ("Expanded into {0} path(s): {1}" -f $expandedPaths.Count, ($expandedPaths -join '; ')) -Level Verbose

        foreach ($p in $expandedPaths) {
            $p = $p -replace '\\{2,}', '\'

            if (-not (Test-Path $p)) {
                Write-Log "File path not found: $p" -Level Verbose
                continue
            }

            if ($PSCmdlet.ShouldProcess($p, "Remove file path")) {
                try {
                    Write-Log "Attempting to remove: $p" -Level Verbose
                    Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed: $p"
                    $removed += $p
                }
                catch {
                    $msg = $_.Exception.Message
                    Write-Log "Initial removal failed for ${p}: $msg" -Level Warning

                    if ($msg -match 'denied' -or $_.Exception -is [System.UnauthorizedAccessException]) {
                        Write-Log "Permission issue detected. Attempting to repair ACLs on $p" -Level Verbose
                        if (Repair-FilePermissions -Path $p) {
                            try {
                                Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                                Write-Log "Removed after repairing permissions: $p" -Level Host
                                $removed += $p
                            }
                            catch {
                                Write-Log "Second removal attempt failed for ${p}: $_" -Level Error
                                $exitCode = 1603
                            }
                        }
                        else {
                            Write-Log "Permission repair failed for $p" -Level Warning
                            $exitCode = 1603
                        }
                    }
                    else {
                        Write-Log "Removal failed for ${p}: $msg" -Level Warning
                        $exitCode = 1603
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Paths    = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: Env Variables ------
#####################################################################################
function Remove-EnvironmentVariables {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$Names)

    # Protect important environment variables
    $protected = @(
        'Path','PATHEXT','OS','ComSpec','SystemRoot',
        'TEMP','TMP',
        'NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE','PROCESSOR_IDENTIFIER','PROCESSOR_LEVEL','PROCESSOR_REVISION',
        'PSModulePath',
        'USERNAME','USERDOMAIN',
        'windir'
    )

    $removed  = @()
    $exitCode = 0

    foreach ($n in $Names) {
        Write-Log "Remove-EnvironmentVariables: Input='$n'" -Level Verbose

        if ($n -in $protected) {
            Write-Log "Skipping protected environment variable: $n" -Level Warning
            continue
        }

        foreach ($scope in "Machine","User") {
            Write-Log "Evaluating removal of $scope variable '$n'" -Level Verbose

            if ($PSCmdlet.ShouldProcess("${scope}:$n", "Remove environment variable")) {
                try {
                    Write-Log "Attempting to remove $scope variable '$n'" -Level Verbose
                    [Environment]::SetEnvironmentVariable($n, $null, $scope)
                    Write-Log "Removed environment variable: ${scope}:$n" -Level Host
                    $removed += "${scope}:$n"
                }
                catch {
                    Write-Log "Failed to remove $scope variable ${n}: $_" -Level Warning
                    $exitCode = 1603
                }
            }
        }
    }

    return [pscustomobject]@{
        ExitCode  = $exitCode
        Variables = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: Path Entries ------
#####################################################################################

function Remove-PathEntry {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$Entries,

        [ValidateSet("Machine","User")]
        [string[]]$Scope = @("Machine")
    )

    $exitCode = 0
    $removed  = @()

    function Invoke-NormalizePathToken {
        param([string]$t)
        if ([string]::IsNullOrWhiteSpace($t)) { return @() }

        $raw = $t.Trim()
        if ($raw.Length -ge 2 -and $raw.StartsWith('"') -and $raw.EndsWith('"')) {
            $raw = $raw.Substring(1, $raw.Length - 2)
        }

        $noTrail         = $raw.TrimEnd('\')
        $expanded        = [Environment]::ExpandEnvironmentVariables($raw)
        $expandedNoTrail = $expanded.TrimEnd('\')

        $out = @()
        foreach ($v in @($raw, $noTrail, $expanded, $expandedNoTrail)) {
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $exists = $false
            foreach ($o in $out) {
                if ($o.Equals($v, [System.StringComparison]::OrdinalIgnoreCase)) { $exists = $true; break }
            }
            if (-not $exists) { $out += $v }
        }
        return $out
    }

    foreach ($s in $Scope) {
        try {
            Write-Log "Remove-PathEntry: Processing scope '$s'" -Level Verbose

            $current = [Environment]::GetEnvironmentVariable("Path", $s)
            if (-not $current) {
                Write-Log "No path defined at $s scope." -Level Verbose
                continue
            }

            $parts = @()
            foreach ($p in $current.Split(';')) {
                if ($null -ne $p) {
                    $t = $p.Trim()
                    if ($t.Length -gt 0) { $parts += $t }
                }
            }
            Write-Log "Current $s path has {0} entries." -f $parts.Count -Level Verbose

            # Build normalization map
            $normMap = @{}
            foreach ($p in $parts) {
                foreach ($n in (Invoke-NormalizePathToken $p)) {
                    if (-not $normMap.ContainsKey($n)) { $normMap[$n] = $p }
                }
            }

            $removedThisScope = @()

            foreach ($entry in $Entries) {
                if ([string]::IsNullOrWhiteSpace($entry)) {
                    Write-Log "Skipping empty path target for $s scope." -Level Verbose
                    continue
                }

                Write-Log "Evaluating entry '$entry' against $s path..." -Level Verbose

                $matchOriginal = $null
                foreach ($tn in (Invoke-NormalizePathToken $entry)) {
                    if ($normMap.ContainsKey($tn)) { $matchOriginal = $normMap[$tn]; break }
                }

                if ($matchOriginal) {
                    Write-Log "Match found in $s path: '$entry' normalized to '$matchOriginal'" -Level Verbose

                    # Always record the match
                    $removedThisScope += $matchOriginal
                    $removed += "${s}:$matchOriginal"

                    # Emit WhatIf preview
                    $null = $PSCmdlet.ShouldProcess($entry, "Remove from $s path")

                    # Only mutate when not WhatIf
                    if (-not $WhatIfPreference) {
                        $filtered = @()
                        foreach ($p in $parts) {
                            if ($p -ne $matchOriginal) { $filtered += $p }
                        }
                        $parts = $filtered
                        foreach ($n in (Invoke-NormalizePathToken $matchOriginal)) {
                            if ($normMap.ContainsKey($n)) { $normMap.Remove($n) | Out-Null }
                        }
                    }
                }
                else {
                    Write-Log "Entry '$entry' not found in $s path." -Level Verbose
                }
            }

            $changed = $removedThisScope.Count -gt 0

            if ($WhatIfPreference) {
                if ($changed) {
                    foreach ($r in $removedThisScope) {
                        Write-Host "[WhatIf] Would remove path entry at $s scope: $r"
                    }
                }
                continue
            }

            if ($changed) {
                $afterPath = ($parts -join ';').Trim(';')
                if ($PSCmdlet.ShouldProcess("$s:Path", "Update path value")) {
                    Write-Log "Updating $s path; removing {0} entries." -f $removedThisScope.Count -Level Verbose
                    [Environment]::SetEnvironmentVariable("Path", $afterPath, $s)
                    foreach ($r in $removedThisScope) {
                        Write-Log "Removed path entry at $s scope: $r" -Level Host
                    }
                }
            }
            else {
                Write-Log "Path unchanged at $s scope; no update performed." -Level Verbose
            }
        }
        catch {
            Write-Log "Failed to update path at $s scope: $_" -Level Warning
            $exitCode = 1603
        }
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Removed  = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: ScheduledTasks ------
#####################################################################################
function Remove-ScheduledTasks {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$TaskNames)

    $removed  = @()
    $exitCode = 0

    foreach ($t in $TaskNames) {
        Write-Log "Remove-ScheduledTasks: Input pattern='$t'" -Level Verbose

        try {
            # Support wildcards by letting Get-ScheduledTask expand patterns
            $tasks = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            if (-not $tasks) {
                Write-Log "No scheduled tasks matched pattern '$t'" -Level Verbose
                continue
            }

            Write-Log "Pattern '$t' expanded into {0} task(s): {1}" -f $tasks.Count, ($tasks.TaskName -join ', ') -Level Verbose

            foreach ($task in $tasks) {
                Write-Log "Evaluating removal of scheduled task: $($task.TaskName)" -Level Verbose

                if ($PSCmdlet.ShouldProcess($task.TaskName, "Remove scheduled task")) {
                    try {
                        Write-Log "Attempting to unregister scheduled task: $($task.TaskName)" -Level Verbose
                        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
                        Write-Log "Removed scheduled task: $($task.TaskName)" -Level Host
                        $removed += $task.TaskName
                    }
                    catch {
                        Write-Log "Failed to remove scheduled task $($task.TaskName): $_" -Level Warning
                        $exitCode = 1603
                    }
                }
            }
        }
        catch {
            Write-Log "Failed to query scheduled task pattern '${t}': $_" -Level Warning
            $exitCode = 1603
        }
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Tasks    = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: Services ------
#####################################################################################
function Remove-Services {
    [CmdletBinding(SupportsShouldProcess)]
    param([string[]]$ServiceNames)

    $removed  = @()
    $exitCode = 0

    foreach ($s in $ServiceNames) {
        Write-Log "Remove-Services: Input='$s'" -Level Verbose

        try {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if ($null -eq $svc) {
                Write-Log "Service not found: $s" -Level Verbose
                continue
            }

            Write-Log "Found service '$s' with status=$($svc.Status) StartType=$($svc.StartType)" -Level Verbose

            if ($PSCmdlet.ShouldProcess($s, "Remove service")) {
                # Stop service if running
                if ($svc.Status -eq 'Running') {
                    try {
                        Write-Log "Attempting to stop running service: $s" -Level Verbose
                        Stop-Service -Name $s -Force -ErrorAction Stop
                        Write-Log "Stopped service: $s" -Level Verbose
                    }
                    catch {
                        Write-Log "Failed to stop service ${s}: $_" -Level Warning
                    }
                }

                try {
                    # Use CIM to delete the service definition
                    Write-Log "Attempting to remove service definition via CIM: $s" -Level Verbose
                    $cimSvc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$s'" -ErrorAction Stop
                    Remove-CimInstance -InputObject $cimSvc -ErrorAction Stop
                    Write-Log "Removed service: $s" -Level Host
                    $removed += $s
                }
                catch {
                    Write-Log "Failed to remove service ${s}: $_" -Level Warning
                    $exitCode = 1603
                }
            }
        }
        catch {
            Write-Log "Failed to query service ${s}: $_" -Level Warning
            $exitCode = 1603
        }
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Services = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: Certificates ------
#####################################################################################
function Remove-Certificates {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string[]]$Thumbprints
    )

    $removed  = @()
    $exitCode = 0

    # Stores to search
    $storeNames = @('Root','My','CA','TrustedPublisher','AuthRoot','TrustedPeople')

    foreach ($t in $Thumbprints) {
        # Normalize thumbprint: strip whitespace only; do not change case
        $normalized = ($t -replace '\s','').Trim()
        Write-Log "Remove-Certificates: Input thumbprint='$normalized'" -Level Verbose

        # 1) Search LocalMachine and CurrentUser of the current context
        foreach ($scope in 'LocalMachine','CurrentUser') {
            foreach ($store in $storeNames) {
                $path = "Cert:\$scope\$store"
                Write-Log "Searching certificate store: $path for thumbprint '$normalized'" -Level Verbose
                try {
                    $certs = Get-ChildItem $path -ErrorAction SilentlyContinue |
                             Where-Object { $_.Thumbprint -eq $normalized }

                    foreach ($cert in $certs) {
                        Write-Log "Found certificate in ${path}: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint)" -Level Verbose

                        if ($PSCmdlet.ShouldProcess("$path\$($cert.Thumbprint)", "Remove certificate")) {
                            if ($WhatIfPreference) {
                                Write-Host "[WhatIf] Would remove certificate: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint) Store=$path"
                                $removed += [pscustomobject]@{
                                    ExitCode  = 0
                                    Thumbprint= $cert.Thumbprint
                                    Subject   = $cert.Subject
                                    StorePath = $path
                                }
                            }
                            else {
                                try {
                                    Write-Log "Attempting to remove certificate: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint) Store=$path" -Level Verbose
                                    Remove-Item -Path $cert.PSPath -Force
                                    Write-Log "Removed certificate: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint)" -Level Host
                                    $removed += [pscustomobject]@{
                                        ExitCode  = 0
                                        Thumbprint= $cert.Thumbprint
                                        Subject   = $cert.Subject
                                        StorePath = $path
                                    }
                                }
                                catch {
                                    Write-Log "Failed to remove certificate $($cert.Thumbprint) from ${path}: $_" -Level Warning
                                    $exitCode = 1603
                                    $removed += [pscustomobject]@{
                                        ExitCode  = $exitCode
                                        Thumbprint= $cert.Thumbprint
                                        Subject   = $cert.Subject
                                        StorePath = $path
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to query $path for thumbprint '$normalized': $($_.Exception.Message)" -Level Warning
                    $exitCode = 1603
                }
            }
        }

        # 2) Search all user hives under HKU via Get-HKUSids
        foreach ($sid in Get-HKUSids) {
            foreach ($store in $storeNames) {
                $path = "Cert:\HKU\$sid\$store"
                Write-Log "Searching certificate store: $path for thumbprint '$normalized'" -Level Verbose
                try {
                    $certs = Get-ChildItem $path -ErrorAction SilentlyContinue |
                             Where-Object { $_.Thumbprint -eq $normalized }

                    foreach ($cert in $certs) {
                        Write-Log "Found certificate in ${path}: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint)" -Level Verbose

                        if ($PSCmdlet.ShouldProcess("$path\$($cert.Thumbprint)", "Remove certificate")) {
                            if ($WhatIfPreference) {
                                Write-Host "[WhatIf] Would remove certificate: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint) Store=$path"
                                $removed += [pscustomobject]@{
                                    ExitCode  = 0
                                    Thumbprint= $cert.Thumbprint
                                    Subject   = $cert.Subject
                                    StorePath = $path
                                }
                            }
                            else {
                                try {
                                    Write-Log "Attempting to remove certificate: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint) Store=$path" -Level Verbose
                                    Remove-Item -Path $cert.PSPath -Force
                                    Write-Log "Removed certificate: Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint)" -Level Host
                                    $removed += [pscustomobject]@{
                                        ExitCode  = 0
                                        Thumbprint= $cert.Thumbprint
                                        Subject   = $cert.Subject
                                        StorePath = $path
                                    }
                                }
                                catch {
                                    Write-Log "Failed to remove certificate $($cert.Thumbprint) from ${path}: $_" -Level Warning
                                    $exitCode = 1603
                                    $removed += [pscustomobject]@{
                                        ExitCode  = $exitCode
                                        Thumbprint= $cert.Thumbprint
                                        Subject   = $cert.Subject
                                        StorePath = $path
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Log "Failed to query $path for thumbprint '$normalized': $($_.Exception.Message)" -Level Warning
                    $exitCode = 1603
                }
            }
        }
    }

    return [pscustomobject]@{
        ExitCode     = $exitCode
        Certificates = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: WMI ------
#####################################################################################
function Remove-WmiEntries {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$Namespaces,
        [string[]]$Classes
    )

    $removed  = @()
    $exitCode = 0

    # Define protected namespaces and classes
    $protectedNamespaces = @(
        'root\cimv2',
        'root\DEFAULT',
        'root\subscription',
        'root\SECURITY',
        'root\WMI',
        'root\Microsoft',
        'root\Policy',
        'root\RSOP',
        'root\Hardware',
        'root\directory'
    )

    $protectedClasses = @(
        '__Namespace',
        '__EventFilter',
        '__InstanceProviderRegistration',
        '__EventConsumer',
        '__FilterToConsumerBinding'
    )

    # Remove classes first
    foreach ($cls in $Classes) {
        Write-Log "Remove-WmiEntries: Input class spec='$cls'" -Level Verbose

        if ($cls -match "^(?<ns>[^:]+):(?<name>.+)$") {
            $ns   = $matches['ns']
            $name = $matches['name']
        }
        else {
            $ns   = "root\cimv2"
            $name = $cls
        }

        # Safety net: block protected namespaces/classes
        if ($ns -in $protectedNamespaces -or $name -in $protectedClasses -or ($ns -eq 'root\cimv2' -and $name -like 'Win32_*')) {
            Write-Log "Skipping protected WMI class: ${ns}:${name}" -Level Warning
            continue
        }

        if ($PSCmdlet.ShouldProcess("${ns}:$name", "Remove WMI class")) {
            try {
                $locator = New-Object -ComObject WbemScripting.SWbemLocator
                $svc = $locator.ConnectServer('.', $ns)

                try {
                    $null = $svc.Get($name)
                    Write-Log "Class '$name' exists in namespace '$ns'" -Level Verbose
                    Write-Log "Attempting to delete WMI class ${ns}:$name" -Level Verbose
                    $svc.Delete($name)
                    $removed += "Class:${ns}:$name"
                    Write-Log "Removed WMI class: ${ns}:$name" -Level Host
                }
                catch {
                    Write-Log "Class '$name' not found in namespace '$ns'" -Level Verbose
                }
            }
            catch {
                Write-Log "Failed to remove WMI class ${ns}:${name}: $($_.Exception.Message)" -Level Warning
                $exitCode = 1603
            }
        }
    }

    # Remove namespaces
    foreach ($ns in $Namespaces) {
        Write-Log "Remove-WmiEntries: Input namespace='$ns'" -Level Verbose

        # Safety net: block protected namespaces
        if ($ns -in $protectedNamespaces) {
            Write-Log "Skipping protected WMI namespace: $ns" -Level Warning
            continue
        }

        if ($PSCmdlet.ShouldProcess($ns, "Remove WMI namespace")) {
            try {
                $childNamespaces = Get-CimInstance -Namespace $ns -ClassName __Namespace -ErrorAction SilentlyContinue
                foreach ($child in $childNamespaces) {
                    $childPath = "$ns\$($child.Name)"
                    Remove-WmiEntries -Namespaces $childPath -WhatIf:$WhatIfPreference
                }

                $parent = Split-Path $ns -Parent
                $name   = Split-Path $ns -Leaf
                $nsObj  = Get-CimInstance -Namespace $parent -ClassName __Namespace -Filter "Name='$name'" -ErrorAction SilentlyContinue
                if ($nsObj) {
                    Remove-CimInstance -InputObject $nsObj -ErrorAction SilentlyContinue
                    $removed += "Namespace:$ns"
                    Write-Log "Removed WMI namespace: $ns" -Level Host
                }
                else {
                    Write-Log "WMI namespace not found: $ns" -Level Verbose
                }
            }
            catch {
                Write-Log "Failed to remove namespace ${ns}: $($_.Exception.Message)" -Level Warning
                $exitCode = 1603
            }
        }
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Wmi      = $removed
    }
}

#####################################################################################
## ------ Functions: MARK: Cleanup ------
#####################################################################################

function Invoke-Cleanup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [pscustomobject]$Cleanup,
        [string]$JobName
    )

    Write-Log "=== Starting cleanup job for $JobName ===" -Level Host

    $exitCodes = @()

    try {
        # Shortcuts
        if ($Cleanup.Shortcuts) {
            foreach ($sc in $Cleanup.Shortcuts) {
                # Skip any shortcut cleanup that lacks a usable Name
                if ($null -eq $sc.Name -or [string]::IsNullOrWhiteSpace([string]$sc.Name)) {
                    Write-Log "Skipping shortcut cleanup entry with empty Name." -Level Verbose
                    continue
                }

                Write-Log "Processing shortcut cleanup for pattern '$($sc.Name)'"
                $result = Remove-Shortcut -Name $sc.Name `
                                          -Lnk:([bool]$sc.Lnk) `
                                          -Url:([bool]$sc.Url) `
                                          -StartMenu:([bool]$sc.StartMenu) `
                                          -Desktop:([bool]$sc.Desktop) `
                                          -Documents:([bool]$sc.Documents) `
                                          -RemoveAll:([bool]$sc.RemoveAll) `
                                          -WhatIf:$WhatIfPreference
                if ($null -ne $result -and $result.ExitCode -is [int]) {
                    $exitCodes += $result.ExitCode
                    Write-Log "Shortcut cleanup exit code: $($result.ExitCode)`n"
                }
            }
        }

        # Registry keys
        if ($Cleanup.RegistryKeys) {
            Write-Log "Processing registry key cleanup"
            $result = Remove-RegistryKeys -Keys $Cleanup.RegistryKeys -WhatIf:$WhatIfPreference
            if ($null -ne $result -and $result.ExitCode -is [int]) {
                $exitCodes += $result.ExitCode
                Write-Log "Registry cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # File paths
        if ($Cleanup.FilePaths) {
            Write-Log "Processing file path cleanup"
            $result = Remove-FilePaths -Paths $Cleanup.FilePaths -WhatIf:$WhatIfPreference
            if ($null -ne $result -and $result.ExitCode -is [int]) {
                $exitCodes += $result.ExitCode
                Write-Log "File path cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # Environment variables
        if ($Cleanup.EnvironmentVariables) {
            Write-Log "Processing environment variable cleanup"
            $result = Remove-EnvironmentVariables -Names $Cleanup.EnvironmentVariables -WhatIf:$WhatIfPreference
            if ($null -ne $result -and $result.ExitCode -is [int]) {
                $exitCodes += $result.ExitCode
                Write-Log "Environment variable cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # PATH entries
        if ($Cleanup.PathEntries) {
            Write-Log "Processing path entry cleanup"
            $result = Remove-PathEntry -Entries $Cleanup.PathEntries -Scope @('Machine') -WhatIf:$WhatIfPreference
            if ($null -ne $result -and $result.ExitCode -is [int]) {
                $exitCodes += $result.ExitCode
                Write-Log "Path entry cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # Scheduled Tasks
        if ($Cleanup.ScheduledTasks) {
            Write-Log "Processing scheduled task cleanup"
            $result = Remove-ScheduledTasks -TaskNames $Cleanup.ScheduledTasks -WhatIf:$WhatIfPreference
            if ($result.ExitCode -is [int]) { 
                $exitCodes += $result.ExitCode
                Write-Log "Scheduled task cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # Services
        if ($Cleanup.Services) {
            Write-Log "Processing service cleanup"
            $result = Remove-Services -ServiceNames $Cleanup.Services -WhatIf:$WhatIfPreference
            if ($result.ExitCode -is [int]) {
                $exitCodes += $result.ExitCode
                Write-Log "Service cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # Certificates
        if ($Cleanup.Certificates) {
            Write-Log "Processing certificate cleanup"
            $result = Remove-Certificates -Thumbprints $Cleanup.Certificates -WhatIf:$WhatIfPreference
            if ($null -ne $result -and $result.ExitCode -is [int]) {
                $exitCodes += $result.ExitCode
                Write-Log "Certificate cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # WMI
        if ($Cleanup.WMI.Namespaces -or $Cleanup.WMI.Classes) {
            Write-Log "Processing WMI cleanup"
            $result = Remove-WmiEntries -Namespaces $Cleanup.WMI.Namespaces `
                                        -Classes $Cleanup.WMI.Classes `
                                        -WhatIf:$WhatIfPreference
            if ($null -ne $result -and $result.ExitCode -is [int]) {
                $exitCodes += $result.ExitCode
                Write-Log "WMI cleanup exit code: $($result.ExitCode)`n"
            }
        }

        # Normalize exit codes
        $exitCodes = @($exitCodes)
        if (-not $exitCodes) { $exitCodes = @(0) }

        $finalExitCode = ($exitCodes | Measure-Object -Maximum).Maximum

        Write-Log "=== Finished cleanup job for $JobName ===" -Level Host
        return [int]$finalExitCode
    }
    catch {
        Write-Log "Cleanup failed: $_" -Level Error
        return 1603
    }
}

Export-ModuleMember -Function `
    Remove-Shortcut, `
    Remove-RegistryKeys, `
    Remove-FilePaths, `
    Remove-EnvironmentVariables, `
    Remove-PathEntry, `
    Remove-ScheduledTasks, `
    Remove-Services, `
    Remove-Certificates, `
    Remove-WmiEntries, `
    Invoke-Cleanup