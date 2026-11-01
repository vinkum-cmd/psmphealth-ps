<#
.SYNOPSIS
  PSMP end-user health test for Windows PowerShell 5.1 (uses the built-in OpenSSH client ssh.exe; no extra modules).
.DESCRIPTION
  One CSV row = one test: log on through a PSMP server as <end user>@<target user>@<target server>, run whoami, stay connected
  for the hold time, run whoami again. Result CSV, a terminal-style screenshot per row and one status mail.
  The end user password comes from CCP (default) or is typed once with -Manual (user name + hidden password).
  Prompts are answered by a tiny helper (SSH_ASKPASS): "reason" -> test.reason, "passcode"/"Passcode" -> test.passcode_answer
  (default = the end user password), "password" -> the end user password. Any other question is logged and reported, never guessed.
  The command run on the target is fixed in this script. Nothing in env.json or the CSV is ever executed.
.EXAMPLE
  .\Run-PsmpHealth.ps1 -Env prod -Validate
  .\Run-PsmpHealth.ps1 -Env prod -Manual -Only 1 -NoMail
#>
[CmdletBinding()]
param(
    [Alias('Env')][string]$EnvName = '',
    [string]$Csv = '',
    [string]$Only = '',
    [switch]$Manual, [switch]$NoMail, [switch]$DryRun, [switch]$Validate, [switch]$SelfTest, [switch]$Version
)
$ErrorActionPreference = 'Stop'
$Script:Root = $PSScriptRoot
$Script:Ver = '0.1.0'
$Script:SshPath = ''            # normally ssh.exe from PATH; the self-test points this at a fake ssh
$Script:SafeValue = '^[A-Za-z0-9._:@/ -]*$'
$Script:HostOk = '^[A-Za-z0-9._:-]{1,253}$'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# ------------------------------------------------------------------ settings and CSV
function Get-Setting($Obj, [string]$Path, $Default = $null) {
    $o = $Obj
    foreach ($k in $Path.Split('.')) {
        if ($null -eq $o) { return $Default }
        $p = $o.PSObject.Properties[$k]
        if ($null -eq $p) { return $Default }
        $o = $p.Value
    }
    if ($null -eq $o) { return $Default }
    return $o
}

$Script:Cols = @{ targetpsmpserver = 'Psmp'; psmpport = 'Port'; targetccpurl = 'CcpUrl'; psmpenduser = 'User'; endusersafe = 'Safe'
    enduserappid = 'AppId'; enduserobjectname = 'Object'; targetuser = 'TUser'; targetserver = 'THost'; holdsec = 'Hold'; retries = 'Retries'; enabled = 'Enabled' }
$Script:Required = @('Psmp', 'CcpUrl', 'User', 'Safe', 'AppId', 'Object', 'TUser', 'THost')
$Script:CcpOnly = @('CcpUrl', 'Safe', 'AppId', 'Object', 'User')       # not needed with -Manual (the user name is typed)

function Get-Defaults($S) {
    $d = @{}
    $pairs = @{ Psmp = 'defaults.psmp_server'; Port = 'defaults.psmp_port'; CcpUrl = 'ccp_url'; User = 'enduser.name'; Safe = 'enduser.ccp.safe'
        AppId = 'enduser.ccp.app_id'; Object = 'enduser.ccp.object'; TUser = 'defaults.target_user'; THost = 'defaults.target_server' }
    foreach ($k in $pairs.Keys) { $v = Get-Setting $S $pairs[$k] ''; if ("$v" -ne '') { $d[$k] = "$v" } }
    return $d
}

function Read-Rows([string]$Path, $Defaults, [bool]$IsManual) {
    $raw = @(Import-Csv -LiteralPath $Path)
    $rows = @()
    if ($raw.Count -eq 0) { return $rows }
    $map = @{}
    foreach ($p in $raw[0].PSObject.Properties.Name) {
        $k = ($p.ToLower() -replace '[^a-z0-9]', '')
        if (-not $Script:Cols.ContainsKey($k)) { throw "$(Split-Path $Path -Leaf): unknown column '$p' - refusing to run (there is no column for commands)" }
        $map[$Script:Cols[$k]] = $p
    }
    $n = 0
    foreach ($r in $raw) {
        $n++
        $vals = @{}; $any = $false
        foreach ($c in $map.Keys) { $x = ('' + $r.($map[$c])).Trim(); $vals[$c] = $x; if ($x -ne '') { $any = $true } }
        if (-not $any) { continue }
        $err = ''; $v = @{}
        foreach ($c in @('Psmp', 'Port', 'CcpUrl', 'User', 'Safe', 'AppId', 'Object', 'TUser', 'THost', 'Hold', 'Retries', 'Enabled')) {
            $x = ''
            if ($vals.ContainsKey($c)) { $x = $vals[$c] }
            if ($x -notmatch $Script:SafeValue) { $err = "column ${c}: characters not allowed"; break }
            if ($x -eq '' -and $Defaults.ContainsKey($c)) { $x = $Defaults[$c] }
            if ($x -notmatch $Script:SafeValue) { $err = "column ${c}: default in env.json has characters that are not allowed"; break }
            if ($x -eq '' -and ($Script:Required -contains $c) -and -not ($IsManual -and ($Script:CcpOnly -contains $c))) { $err = "column ${c}: required (no value and no default in env.json)"; break }
            $v[$c] = $x
        }
        $retries = -1; $enabled = $true
        if (-not $err) {
            if ($v.CcpUrl -ne '' -and $v.CcpUrl -notmatch '^https://') { $v.CcpUrl = 'https://' + ($v.CcpUrl -replace '^http://', '') }
            if ($v.Psmp -notmatch $Script:HostOk) { $err = 'TargetPSMPServer must be a host name or IPv4 address' }
            elseif ($v.THost -notmatch $Script:HostOk) { $err = 'TargetServer must be a host name or IPv4 address' }
            elseif ($v.User -match ' ' -or $v.TUser -match ' ') { $err = 'PSMPEnduser and TargetUser must not contain spaces' }
            elseif ($v.Port -ne '' -and -not ($v.Port -match '^\d+$' -and [int]$v.Port -ge 1 -and [int]$v.Port -le 65535)) { $err = 'PSMPPort must be 1-65535' }
            elseif ($v.Hold -ne '' -and -not ($v.Hold -match '^\d+$' -and [int]$v.Hold -ge 10 -and [int]$v.Hold -le 900)) { $err = 'HoldSec must be a whole number from 10 to 900' }
            elseif ($v.Retries -ne '' -and $v.Retries -notmatch '^[012]$') { $err = 'Retries must be 0, 1 or 2' }
            else {
                $ev = $v.Enabled.ToLower(); if ($ev -eq '') { $ev = 'yes' }
                if (@('yes', 'no', 'true', 'false', '1', '0') -notcontains $ev) { $err = 'Enabled must be yes or no' }
                else { $enabled = (@('yes', 'true', '1') -contains $ev) }
            }
            if (-not $err -and $v.Retries -ne '') { $retries = [int]$v.Retries }
        }
        $rows += [pscustomobject]@{ N = $n; V = $v; Err = $err; Retries = $retries; Enabled = $enabled }
    }
    return $rows
}

# ------------------------------------------------------------------ network checks (IPv4 only)
function Get-Ipv4([string]$HostName) {
    try { return @([System.Net.Dns]::GetHostAddresses($HostName) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() }) }
    catch { return @() }
}
function Test-Tcp([string]$HostName, [int]$Port, [int]$Ms = 4000) {
    $ips = @(Get-Ipv4 $HostName)
    if ($ips.Count -eq 0) { return $false }
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ips[0], $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($Ms, $false)) { return $false }
        try { $c.EndConnect($iar) } catch { return $false }
        return $c.Connected
    } finally { $c.Close() }
}
function Test-Http([string]$Url) {
    try { $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 8; return [int]$r.StatusCode }
    catch { if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode } else { return 0 } }
}
function Test-PsmpHost([string]$HostName, [string]$Port) {
    if ($Port -eq '') { $Port = '22' }
    $ips = @(Get-Ipv4 $HostName)
    if ($ips.Count -eq 0) { return @($false, "PSMP server name '$HostName' does not resolve in DNS") }
    if (-not (Test-Tcp $HostName ([int]$Port))) { return @($false, "PSMP server $HostName ($($ips -join ', ')) not reachable on TCP $Port") }
    return @($true, "${HostName}:$Port -> $($ips -join ', ')")
}

# ------------------------------------------------------------------ CCP and secrets
function ConvertTo-Plain([System.Security.SecureString]$Sec) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Sec)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringAuto($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
function Get-CcpPassword($V, [string]$Reason, [string]$Thumb) {
    $e = { param($s) [uri]::EscapeDataString($s) }
    $q = 'AppID=' + (& $e $V.AppId) + '&Safe=' + (& $e $V.Safe) + '&Folder=Root&Object=' + (& $e $V.Object) + '&Reason=' + (& $e $Reason)
    $p = @{ Uri = ($V.CcpUrl.TrimEnd('/') + '/AIMWebService/api/Accounts?' + $q); Method = 'Get'; TimeoutSec = 20 }
    if ($Thumb) { $p.Certificate = (Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumb" -ErrorAction Stop) }
    try { $r = Invoke-RestMethod @p }
    catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { try { $j = $_.ErrorDetails.Message | ConvertFrom-Json; $msg = "$($j.ErrorCode) $($j.ErrorMsg)" } catch { } }
        if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
        throw "CCP call failed: $msg"
    }
    if (-not $r.Content) { throw 'CCP returned no password' }
    return @{ User = "$($r.UserName)"; Pw = "$($r.Content)" }
}

# ------------------------------------------------------------------ the SSH_ASKPASS helper (static text, holds no secret)
function New-Helper([string]$Dir) {
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $cmd = @'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0askpass.ps1" %*
'@
    $ps = @'
$p = ($args -join ' ').Trim('"')
$kind = 'unknown'; $a = ''
if ($p -match '(?i)reason') { $kind = 'reason'; $a = $env:PSMPH_REASON }
elseif ($p -match '(?i)pass\s?code|one[- ]?time|\botp\b') { $kind = 'passcode'; $a = $env:PSMPH_PASSCODE }
elseif ($p -match '(?i)password') { $kind = 'password'; $a = $env:PSMPH_PW }
if ($env:PSMPH_LOG) { Add-Content -LiteralPath $env:PSMPH_LOG -Value ($kind + "`t" + $p) -Encoding ASCII }
[Console]::Out.Write($a + "`n")
'@
    Set-Content -LiteralPath (Join-Path $Dir 'askpass.cmd') -Value $cmd -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $Dir 'askpass.ps1') -Value $ps -Encoding ASCII
}

# ------------------------------------------------------------------ one ssh session
function Invoke-Session($V, [string]$User, [string]$Pw, [int]$Hold, [string]$Reason, [string]$Passcode, [string]$HelperDir, [string]$PromptLog, [string]$KnownHosts, [int]$MfaWait) {
    $ssh = $Script:SshPath
    if (-not $ssh) { $c = Get-Command ssh.exe -ErrorAction SilentlyContinue; if ($c) { $ssh = $c.Source } }
    if (-not $ssh) { return @{ Out = 'ssh.exe not found (install the Windows optional feature "OpenSSH Client")'; Code = -1; TimedOut = $false } }
    $port = '22'; if ($V.Port -ne '') { $port = $V.Port }
    $remote = 'echo S1 $(date +%s) $(whoami); sleep ' + $Hold + '; echo S2 $(date +%s) $(whoami)'     # FIXED command, no quotes or user input in it
    $arg = '-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=' + $KnownHosts + '" -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 ' +
           '-o PreferredAuthentications=keyboard-interactive,password -p ' + $port + ' -l "' + $User + '@' + $V.TUser + '@' + $V.THost + '" ' + $V.Psmp + ' "' + $remote + '"'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ssh; $psi.Arguments = $arg; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    # the secrets exist only in the environment of this one child process, never in the PowerShell session
    $psi.EnvironmentVariables['SSH_ASKPASS'] = (Join-Path $HelperDir 'askpass.cmd')
    $psi.EnvironmentVariables['SSH_ASKPASS_REQUIRE'] = 'force'
    $psi.EnvironmentVariables['PSMPH_PW'] = $Pw
    $psi.EnvironmentVariables['PSMPH_REASON'] = $Reason
    $psi.EnvironmentVariables['PSMPH_PASSCODE'] = $Passcode
    $psi.EnvironmentVariables['PSMPH_LOG'] = $PromptLog
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $so = $p.StandardOutput.ReadToEndAsync(); $se = $p.StandardError.ReadToEndAsync()
    $timed = $false
    if (-not $p.WaitForExit(($Hold + 120 + $MfaWait) * 1000)) { $timed = $true; try { $p.Kill() } catch { } }
    $p.WaitForExit()
    $text = ($so.Result + "`n" + $se.Result)
    if ($Pw) { $text = $text.Replace($Pw, '********') }
    return @{ Out = $text; Code = $p.ExitCode; TimedOut = $timed }
}

function Get-Verdict([string]$Text, [int]$Code, [bool]$TimedOut, [string]$TUser, [int]$Hold, [string[]]$Prompts) {
    $r = @{ Steps = @{ login = 'FAIL'; identity = 'not run'; hold = 'not run' }; Failed = ''; Reason = ''; Gap = 0; Rejected = $false }
    $pw = @($Prompts | Where-Object { $_ -like "password`t*" }).Count
    $unk = @($Prompts | Where-Object { $_ -like "unknown`t*" })
    $m1 = [regex]::Match($Text, '(?m)^S1 (\d+) (\S+)\s*$'); $m2 = [regex]::Match($Text, '(?m)^S2 (\d+) (\S+)\s*$')
    if (-not $m1.Success) {
        $r.Failed = 'login'
        $am = [regex]::Match($Text, 'Failed to obtain account[^\r\n]{0,260}')
        if ($pw -ge 2) { $r.Reason = 'login: password prompted again - login rejected'; $r.Rejected = $true }
        elseif ($unk.Count -gt 0) { $r.Reason = "login: PSMP asked a question the tool cannot answer: '" + ($unk[0] -replace "^unknown`t", '') + "'" }
        elseif ($am.Success) { $r.Reason = 'login: ' + $am.Value }
        elseif ($Text -match '(?i)permission denied|access denied') { $r.Reason = 'login: permission denied (check user, password and target account)'; $r.Rejected = $true }
        elseif ($TimedOut) { $r.Reason = 'login: timed out waiting for the login (approve the MFA push in time, or raise test.mfa_wait_sec)' }
        else { $r.Reason = "login: no shell reached through PSMP (ssh exit code $Code)" }
        return $r
    }
    $r.Steps.login = 'OK'
    $u1 = $m1.Groups[2].Value; $u2 = ''; if ($m2.Success) { $u2 = $m2.Groups[2].Value }
    if ($u1 -eq $TUser -and ($u2 -eq '' -or $u2 -eq $TUser)) { $r.Steps.identity = 'OK' }
    else { $r.Steps.identity = 'FAIL'; $r.Failed = 'identity'; $r.Reason = "identity: whoami is '$u1' " + $(if ($u2) { "then '$u2' " } else { '' }) + "expected '$TUser'" }
    if (-not $m2.Success) {
        $r.Steps.hold = 'FAIL'; if (-not $r.Failed) { $r.Failed = 'hold'; $r.Reason = "hold: second whoami missing: session dropped before ${Hold}s (ssh exit code $Code)" }
    } else {
        $r.Gap = [int]$m2.Groups[1].Value - [int]$m1.Groups[1].Value
        if ($r.Gap -ge ($Hold - 2) -and $Code -eq 0) { $r.Steps.hold = 'OK' }
        else { $r.Steps.hold = 'FAIL'; if (-not $r.Failed) { $r.Failed = 'hold'; $r.Reason = "hold: gap between whoami calls $($r.Gap)s (expected >= ${Hold}s), ssh exit code $Code" } }
    }
    return $r
}

# ------------------------------------------------------------------ screenshot (terminal-style PNG)
function New-ShotPng([string[]]$Lines, [string]$Path, [string]$Title, [string]$Verdict, [int]$Width = 110, [int]$MaxLines = 40) {
    Add-Type -AssemblyName System.Drawing
    $wrapped = New-Object System.Collections.ArrayList
    foreach ($l in $Lines) {
        $t = ($l -replace "`t", '    ') -replace '[\x00-\x08\x0B-\x1F]', ''
        if ($t.Length -le $Width) { [void]$wrapped.Add($t) }
        else { for ($i = 0; $i -lt $t.Length; $i += $Width) { $pre = ''; if ($i -gt 0) { $pre = '    ' }; [void]$wrapped.Add($pre + $t.Substring($i, [Math]::Min($Width, $t.Length - $i))) } }
    }
    if ($wrapped.Count -eq 0) { [void]$wrapped.Add('(no output)') }
    if ($wrapped.Count -gt $MaxLines) {
        $h = [int]($MaxLines / 2); $all = @($wrapped); $wrapped = New-Object System.Collections.ArrayList
        foreach ($x in $all[0..($h - 1)]) { [void]$wrapped.Add($x) }
        [void]$wrapped.Add("... ($($all.Count - $MaxLines) lines omitted; see the detail log) ...")
        foreach ($x in $all[($all.Count - $h)..($all.Count - 1)]) { [void]$wrapped.Add($x) }
    }
    $font = New-Object System.Drawing.Font('Consolas', 10)
    $probe = New-Object System.Drawing.Bitmap 10, 10; $g0 = [System.Drawing.Graphics]::FromImage($probe)
    $fmt = [System.Drawing.StringFormat]::GenericTypographic
    $cw = $g0.MeasureString('MMMMMMMMMM', $font, 2000, $fmt).Width / 10; $lh = $font.GetHeight($g0) + 3
    $g0.Dispose(); $probe.Dispose()
    $bar = 28; $w = [int]($cw * $Width) + 24; $h = [int]($bar + 12 + $lh * $wrapped.Count + 12)
    $bmp = New-Object System.Drawing.Bitmap $w, $h; $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.Clear([System.Drawing.Color]::FromArgb(24, 24, 24))
        $ok = ($Verdict -eq 'PASS'); $barCol = [System.Drawing.Color]::FromArgb(179, 38, 30); if ($ok) { $barCol = [System.Drawing.Color]::FromArgb(46, 125, 50) }
        $g.FillRectangle((New-Object System.Drawing.SolidBrush $barCol), 0, 0, $w, $bar)
        $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
        $g.DrawString("$Title  -  $Verdict", $font, $white, 8, 6, $fmt)
        $y = $bar + 10
        foreach ($l in $wrapped) {
            $col = [System.Drawing.Color]::FromArgb(230, 230, 230)
            if ($l -match '(?i)FAIL|denied|refused|timed out|error') { $col = [System.Drawing.Color]::FromArgb(255, 140, 130) }
            elseif ($l -match '\bOK\b|^S[12] ') { $col = [System.Drawing.Color]::FromArgb(140, 230, 150) }
            $g.DrawString($l, $font, (New-Object System.Drawing.SolidBrush $col), 10, $y, $fmt); $y += $lh
        }
        $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $g.Dispose(); $bmp.Dispose(); $font.Dispose() }
    return $Path
}

# ------------------------------------------------------------------ report and mail
function Build-Report($Results, [string]$RunId, [string]$Note) {
    $nfail = @($Results | Where-Object { $_.Result -ne 'PASS' }).Count; $nok = $Results.Count - $nfail
    $head = "ALL OK ($nok tests)"; if ($nfail) { $head = "$nfail FAILED, $nok OK" }
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $col = '#2e7d32'; if ($nfail) { $col = '#b3261e' }
    $t = New-Object System.Collections.ArrayList; $h = New-Object System.Collections.ArrayList
    [void]$t.Add("PSMP HEALTH TEST - $head"); [void]$t.Add("Run $RunId | host $env:COMPUTERNAME | $Note"); [void]$t.Add('')
    [void]$h.Add("<html><body style=`"font-family:Segoe UI,Arial,sans-serif;font-size:13px`"><div style=`"padding:10px 14px;color:#fff;background:$col;font-size:16px`"><b>PSMP health test - $(& $enc $head)</b></div>")
    [void]$h.Add("<p>Run <b>$(& $enc $RunId)</b> &middot; host $(& $enc $env:COMPUTERNAME) &middot; $(& $enc $Note)</p>")
    [void]$h.Add('<table cellpadding="5" style="border-collapse:collapse;border:1px solid #ccc"><tr style="background:#eee"><th>#</th><th>PSMP server</th><th>End user</th><th>Target</th><th>Result</th><th>CCP</th><th>Login</th><th>Identity</th><th>Hold</th><th>Secs</th></tr>')
    foreach ($r in $Results) {
        [void]$t.Add(('{0,-3}{1,-24}{2,-36}{3,-7}{4}' -f $r.Row, $r.TargetPSMPServer, ($r.TargetUser + '@' + $r.TargetServer), $r.Result, $r.FailedStep))
        $bg = '#2e7d32'; if ($r.Result -ne 'PASS') { $bg = '#b3261e' }
        $cells = ''
        foreach ($s in @('ccp', 'login', 'identity', 'hold')) { $x = $r.$s; $sym = '&ndash;'; if ($x -eq 'OK') { $sym = '&#10003;' } elseif ($x -eq 'FAIL') { $sym = '&#10007;' } elseif ($x -eq 'skipped') { $sym = 'skip' }; $cells += "<td align=`"center`">$sym</td>" }
        [void]$h.Add("<tr style=`"border-top:1px solid #ddd`"><td>$($r.Row)</td><td>$(& $enc $r.TargetPSMPServer)</td><td>$(& $enc $r.PSMPEnduser)</td><td>$(& $enc ($r.TargetUser + '@' + $r.TargetServer))</td><td style=`"color:#fff;background:$bg`" align=`"center`"><b>$($r.Result)</b></td>$cells<td>$($r.Seconds)s</td></tr>")
    }
    [void]$h.Add('</table>')
    foreach ($r in @($Results | Where-Object { $_.Result -ne 'PASS' })) {
        [void]$t.Add(''); [void]$t.Add("Row $($r.Row) FAILED at step $($r.FailedStep): $($r.Reason)"); [void]$t.Add("  Detail log on $($env:COMPUTERNAME): $($r.DetailLog)")
        [void]$h.Add("<div style=`"border-left:4px solid #b3261e;padding:4px 12px;margin:10px 0;background:#fdf3f2`"><b>Row $($r.Row)</b> failed at <b>$(& $enc $r.FailedStep)</b><br><b>Reason:</b> $(& $enc $r.Reason)<br><span style=`"color:#666`">Detail log on $(& $enc $env:COMPUTERNAME): $(& $enc $r.DetailLog)</span></div>")
    }
    $shots = @($Results | Where-Object { $_.Screenshot })
    if ($shots.Count) {
        [void]$h.Add('<h3>Session screenshots</h3>')
        foreach ($r in $shots) { [void]$h.Add("<p style=`"margin:10px 0 2px`"><b>Row $($r.Row)</b> &middot; $(& $enc $r.TargetPSMPServer) &rarr; $(& $enc ($r.TargetUser + '@' + $r.TargetServer)) &middot; $($r.Result)</p><img src=`"cid:shot$($r.Row)`" style=`"max-width:100%;border:1px solid #ccc`">") }
    }
    [void]$h.Add('</body></html>')
    return @{ Head = $head; Text = ($t -join "`r`n"); Html = ($h -join "`r`n") }
}

function Send-Report($Mail, [string]$Subject, $Report, $Results, [string]$CsvPath) {
    $m = New-Object System.Net.Mail.MailMessage
    $m.From = New-Object System.Net.Mail.MailAddress($Mail.from)
    foreach ($to in @($Mail.to)) { $m.To.Add($to) }
    $m.Subject = $Subject
    $m.AlternateViews.Add([System.Net.Mail.AlternateView]::CreateAlternateViewFromString($Report.Text, $null, 'text/plain'))
    $hv = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString($Report.Html, $null, 'text/html')
    foreach ($r in @($Results | Where-Object { $_.Screenshot -and (Test-Path -LiteralPath $_.Screenshot) })) {
        $lr = New-Object System.Net.Mail.LinkedResource($r.Screenshot, 'image/png'); $lr.ContentId = "shot$($r.Row)"; $hv.LinkedResources.Add($lr)
    }
    $m.AlternateViews.Add($hv)
    if ($CsvPath -and (Test-Path -LiteralPath $CsvPath)) { $m.Attachments.Add((New-Object System.Net.Mail.Attachment($CsvPath))) }
    $port = 25; if ($Mail.smtp_port) { $port = [int]$Mail.smtp_port }
    $c = New-Object System.Net.Mail.SmtpClient($Mail.smtp_host, $port); $c.Timeout = 20000
    try { $c.Send($m) } finally { $m.Dispose(); $c.Dispose() }
}

# ------------------------------------------------------------------ one row (CCP or manual password, retries, screenshot)
function Invoke-Row($Row, $Cfg, $Paths, [string]$RunDir, [string]$HelperDir, [bool]$IsManual, [string]$MPw, [string]$MUser, [bool]$Rejected) {
    $RV = $Row.V; $t0 = Get-Date
    $res = @{ Result = 'FAIL'; Failed = ''; Reason = ''; Steps = @{ ccp = 'not run'; login = 'not run'; identity = 'not run'; hold = 'not run' }; Gap = 0; Attempts = 0; Log = ''; Shot = ''; Rejected = $false }
    $notes = New-Object System.Collections.ArrayList
    $note = { param($m) [void]$notes.Add(('[{0:HH:mm:ss}] {1}' -f (Get-Date), $m)) }
    $hold = [int](Get-Setting $Cfg 'test.hold_seconds' 60); if ($RV.Hold -ne '') { $hold = [int]$RV.Hold }
    $reason = [string](Get-Setting $Cfg 'test.reason' 'automated psmp health test')
    $mfa = [int](Get-Setting $Cfg 'test.mfa_wait_sec' 60)
    $user = $RV.User; if ($IsManual) { $user = $MUser }
    if ($Rejected) { $res.Failed = 'skipped'; $res.Reason = 'skipped: PSMP rejected the manual password on an earlier row (stopped to avoid locking the account)' }
    elseif ($Row.Err) { $res.Failed = 'input'; $res.Reason = $Row.Err }
    else {
        $pre = $true; $premsg = ''
        if ([bool](Get-Setting $Cfg 'prechecks.enabled' $true)) { $pc = Test-PsmpHost $RV.Psmp $RV.Port; $pre = $pc[0]; $premsg = $pc[1] }
        if (-not $pre) { $res.Failed = 'precheck'; $res.Reason = 'precheck: ' + $premsg }
        else {
            $maxtry = 1 + [int](Get-Setting $Cfg 'reliability.retries' 1); if ($Row.Retries -ge 0) { $maxtry = 1 + $Row.Retries }
            $wait = [int](Get-Setting $Cfg 'reliability.retry_wait_sec' 30)
            $pca = [string](Get-Setting $Cfg 'test.passcode_answer' 'password')
            if ($pca -eq 'ask') { $x = Read-Host "Row $($Row.N): passcode / OTP now (Enter = 1, Duo push)" -AsSecureString; $pca = ConvertTo-Plain $x; if (-not $pca) { $pca = '1' } }
            for ($try = 1; $try -le $maxtry; $try++) {
                $res.Attempts = $try; $res.Failed = ''; $res.Reason = ''; $res.Rejected = $false; $res.Steps = @{ ccp = 'not run'; login = 'not run'; identity = 'not run'; hold = 'not run' }
                $pw = $MPw
                if ($IsManual) { $res.Steps.ccp = 'skipped'; & $note 'manual password in use (CCP skipped, password not shown)' }
                else {
                    & $note "fetching the end user's password from CCP ($($RV.CcpUrl) AppID=$($RV.AppId) Safe=$($RV.Safe))"
                    try {
                        $thumb = [string](Get-Setting $Cfg 'credentials.ccp.client_certificate_thumbprint' '')
                        $c = Get-CcpPassword $V $reason $thumb
                        if ($c.User -ne $user) { throw "CCP account user name is '$($c.User)', expected '$user' (wrong object?)" }
                        $pw = $c.Pw; $res.Steps.ccp = 'OK'; & $note "CCP OK (password length $($pw.Length), not shown)"
                    } catch { $res.Steps.ccp = 'FAIL'; $res.Failed = 'ccp'; $res.Reason = "ccp: $($_.Exception.Message)"; & $note $res.Reason }
                }
                if ($res.Steps.ccp -ne 'FAIL') {
                    $plog = Join-Path $HelperDir ("prompts-row$($Row.N)-try$try.log"); Set-Content -LiteralPath $plog -Value '' -Encoding ASCII
                    & $note "connecting: $user@$($RV.TUser)@$($RV.THost) via $($RV.Psmp) (hold ${hold}s)"
                    $pcUse = $pca; if ($pca -eq 'password') { $pcUse = $pw }          # test.passcode_answer = password: the passcode prompt gets the end user password
                    $ses = Invoke-Session $RV $user $pw $hold $reason $pcUse $HelperDir $plog $Paths.known_hosts $mfa
                    $prompts = @(Get-Content -LiteralPath $plog | Where-Object { $_ })
                    foreach ($l in ($ses.Out -split "`r?`n")) { if ($l.Trim()) { [void]$notes.Add('    ssh: ' + $l) } }
                    foreach ($p in $prompts) { $pp = $p -split "`t", 2; [void]$notes.Add('    prompt ' + $pp[0] + ': "' + $pp[1] + '"  (answered by the helper)') }
                    $vd = Get-Verdict $ses.Out $ses.Code $ses.TimedOut $RV.TUser $hold $prompts
                    $res.Steps.login = $vd.Steps.login; $res.Steps.identity = $vd.Steps.identity; $res.Steps.hold = $vd.Steps.hold; $res.Gap = $vd.Gap
                    $res.Failed = $vd.Failed; $res.Reason = $vd.Reason; $res.Rejected = $vd.Rejected
                    $pw = $null
                }
                if (-not $res.Failed) { $res.Result = 'PASS'; break }
                if ($IsManual -and $res.Rejected) { break }                      # never send a rejected password twice
                if ($try -lt $maxtry) { & $note "attempt $try failed at $($res.Failed) - retrying in ${wait}s"; Start-Sleep -Seconds $wait }
            }
        }
    }
    $lf = Join-Path $RunDir ("row-$($Row.N).out")
    $body = @($notes) + @("RESULT: $($res.Result)" + $(if ($res.Failed) { " at step $($res.Failed): $($res.Reason)" } else { '' }))
    Set-Content -LiteralPath $lf -Value $body -Encoding UTF8; $res.Log = $lf
    $mode = ([string](Get-Setting $Cfg 'outputs.screenshots' 'all')).ToLower()
    if ($mode -ne 'off' -and -not ($mode -eq 'failures' -and $res.Result -eq 'PASS')) {
        try { $res.Shot = New-ShotPng $body (Join-Path $RunDir "row-$($Row.N).screen.png") "Row $($Row.N): $user -> $($RV.Psmp) -> $($RV.TUser)@$($RV.THost)" $res.Result }
        catch { Write-Host "           row $($Row.N): screenshot not created ($($_.Exception.Message))" }
    }
    $res.Secs = [int]((Get-Date) - $t0).TotalSeconds
    return $res
}

# ------------------------------------------------------------------ self-test (no PSMP, no network needed)
function Invoke-SelfTest {
    $Script:SelfFail = 0; $Script:SelfTotal = 0
    function Check([string]$Name, [bool]$Cond, [string]$Info = '') { $Script:SelfTotal++; if ($Cond) { Write-Host "  [ok]   $Name" } else { Write-Host "  [FAIL] $Name $Info" -ForegroundColor Red; $Script:SelfFail++ } }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('psmph-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "psmphealth $Script:Ver self-test (temp folder $tmp)"
        Write-Host '1. CSV rules'
        $d = @{ Psmp = 'psmp.test'; CcpUrl = 'ccp.test'; User = 'u1'; Safe = 'S'; AppId = 'A'; Object = 'O' }
        $f = Join-Path $tmp 't.csv'
        Set-Content $f "TargetUser,TargetServer`nroot,srv1" -Encoding ASCII
        $r = @(Read-Rows $f $d $false); Check 'defaults fill the row' ($r.Count -eq 1 -and $r[0].Err -eq '' -and $r[0].V.Psmp -eq 'psmp.test' -and $r[0].V.CcpUrl -eq 'https://ccp.test')
        Set-Content $f "TargetUser,TargetServer,HoldSec`nroot,srv1,5" -Encoding ASCII; Check 'HoldSec 5 rejected' ((@(Read-Rows $f $d $false))[0].Err -like '*HoldSec*')
        Set-Content $f "TargetUser,TargetServer,TargetPSMPServer`nroot,srv1,a;b" -Encoding ASCII; Check 'bad characters rejected' ((@(Read-Rows $f $d $false))[0].Err -like '*not allowed*')
        Set-Content $f "TargetUser,TargetServer,Enabled.`nroot,srv1," -Encoding ASCII; $x = @(Read-Rows $f $d $false); Check "header 'Enabled.' and blank value mean yes" ($x[0].Err -eq '' -and $x[0].Enabled)
        Set-Content $f "TargetUser,TargetServer,Command`nroot,srv1,id" -Encoding ASCII; $thrown = $false; try { [void](Read-Rows $f $d $false) } catch { $thrown = $true }; Check 'a Command column is refused' $thrown
        Set-Content $f "TargetUser,TargetServer`nroot,srv1" -Encoding ASCII; Check 'manual mode needs no CCP values' ((@(Read-Rows $f @{ Psmp = 'p.test' } $true))[0].Err -eq '')
        Write-Host '2. Network helpers'
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $port = $l.LocalEndpoint.Port
        Check 'open port detected' (Test-Tcp 'localhost' $port 2000); $l.Stop(); Check 'closed port detected' (-not (Test-Tcp 'localhost' $port 1500))
        Write-Host '3. Prompt helper (SSH_ASKPASS)'
        $hd = Join-Path $tmp 'helper'; New-Helper $hd; $ask = Join-Path $hd 'askpass.cmd'; $plog = Join-Path $tmp 'p.log'; Set-Content $plog '' -Encoding ASCII
        $nasty = 'a&b|c%d!e^f"g h'
        $env:PSMPH_PW = $nasty; $env:PSMPH_REASON = 'why not'; $env:PSMPH_PASSCODE = '1'; $env:PSMPH_LOG = $plog
        try {
            $a1 = ((& $ask '(u@t@h@p) Vault Password:') | Select-Object -First 1); Check 'password prompt answered (special characters intact)' ($a1 -eq $nasty) "got [$a1]"
            $a2 = ((& $ask '(u@t@h@p) You are required to specify a reason for this operation:') | Select-Object -First 1); Check 'reason prompt answered' ($a2 -eq 'why not')
            $a3 = ((& $ask 'Duo Passcode or option (1-1):') | Select-Object -First 1); Check 'Passcode prompt answered' ($a3 -eq '1')
            $a3b = ((& $ask 'enter your passcode:') | Select-Object -First 1); Check 'passcode (lower case) answered' ($a3b -eq '1')
            $a4 = ((& $ask 'Something strange?') | Select-Object -First 1); Check 'unknown prompt answered with nothing' ([string]$a4 -eq '')
        } finally { Remove-Item Env:PSMPH_PW, Env:PSMPH_REASON, Env:PSMPH_PASSCODE, Env:PSMPH_LOG -ErrorAction SilentlyContinue }
        $kinds = @(Get-Content $plog | Where-Object { $_ } | ForEach-Object { ($_ -split "`t")[0] }); Check 'prompt log records kinds, not answers' (($kinds -join ',') -eq 'password,reason,passcode,passcode,unknown' -and -not ((Get-Content $plog -Raw) -like "*$nasty*"))
        Write-Host '4. Verdicts'
        $v = Get-Verdict "S1 1000 root`nS2 1060 root" 0 $false 'root' 60 @(); Check 'PASS output' ($v.Steps.login -eq 'OK' -and $v.Steps.identity -eq 'OK' -and $v.Steps.hold -eq 'OK' -and $v.Gap -eq 60 -and -not $v.Failed)
        $v = Get-Verdict "S1 1000 bob`nS2 1060 bob" 0 $false 'root' 60 @(); Check 'wrong user detected' ($v.Failed -eq 'identity')
        $v = Get-Verdict "S1 1000 root" 255 $false 'root' 60 @(); Check 'dropped session detected' ($v.Failed -eq 'hold')
        $v = Get-Verdict 'Failed to obtain account. Error: [076E Password object was not found]' 255 $false 'root' 60 @(); Check 'PSMP account error shown' ($v.Failed -eq 'login' -and $v.Reason -like '*076E*')
        $v = Get-Verdict '' 255 $false 'root' 60 @("password`tVault Password:", "password`tVault Password:"); Check 'second password prompt = rejected' ($v.Rejected)
        $v = Get-Verdict '' 255 $false 'root' 60 @("unknown`tWhat colour?"); Check 'unknown question reported' ($v.Reason -like '*What colour?*')
        Write-Host '5. Whole pipeline with a fake ssh'
        $fps = Join-Path $tmp 'fake-ssh.ps1'
        Set-Content $fps @'
$remote = $args[$args.Count - 1]; $hold = 10; if ($remote -match 'sleep (\d+)') { $hold = [int]$Matches[1] }
$ask = $env:SSH_ASKPASS
$a = (& $ask '(u@t@h@p) Vault Password:' | Select-Object -First 1)
if ($a -ne $env:PSMPH_FAKE_EXPECT) { [void](& $ask '(u@t@h@p) Vault Password:'); [Console]::Error.WriteLine('Permission denied'); exit 255 }
[void](& $ask '(u@t@h@p) You are required to specify a reason for this operation:')
if ($env:PSMPH_FAKE_MFA -eq '1') { [void](& $ask 'Duo passcode or option:') }
$t = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
"S1 $t $env:PSMPH_FAKE_USER"; "S2 $($t + $hold) $env:PSMPH_FAKE_USER"
'@ -Encoding ASCII
        Set-Content (Join-Path $tmp 'fake-ssh.cmd') "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0fake-ssh.ps1`" %*" -Encoding ASCII
        $Script:SshPath = Join-Path $tmp 'fake-ssh.cmd'
        $S = ('{"test":{"hold_seconds":10,"reason":"selftest reason","passcode_answer":"1","mfa_wait_sec":5},"reliability":{"retries":0},"prechecks":{"enabled":false},"outputs":{"screenshots":"all"}}' | ConvertFrom-Json)
        $paths = @{ known_hosts = (Join-Path $tmp 'kh') }; $rd = Join-Path $tmp 'run'; New-Item -ItemType Directory -Path $rd | Out-Null
        Set-Content $f "TargetUser,TargetServer`nroot,srv1" -Encoding ASCII; $row = (@(Read-Rows $f @{ Psmp = 'psmp.test' } $true))[0]
        $env:PSMPH_FAKE_EXPECT = 'Right Pw!'; $env:PSMPH_FAKE_USER = 'root'; $env:PSMPH_FAKE_MFA = '1'
        try {
            $res = Invoke-Row $row $S $paths $rd $hd $true 'Right Pw!' 'typed-user' $false
            Check 'good password: PASS through the helper' ($res.Result -eq 'PASS' -and $res.Steps.ccp -eq 'skipped' -and $res.Gap -eq 10) "got $($res.Result) $($res.Reason)"
            Check 'passcode prompt was answered during the session' ((Get-Content (Join-Path $hd 'prompts-row1-try1.log') -Raw) -like '*passcode*')
            Check 'secrets are not in the PowerShell session' (-not $env:PSMPH_PW -and -not $env:SSH_ASKPASS)
            Check 'detail log has no password' (-not ((Get-Content $res.Log -Raw) -like '*Right Pw!*'))
            $res2 = Invoke-Row $row $S $paths $rd $hd $true 'WRONG' 'typed-user' $false
            Check 'wrong password: FAIL + rejected flag' ($res2.Result -eq 'FAIL' -and $res2.Rejected -and $res2.Reason -like '*rejected*') "got $($res2.Reason)"
            $res3 = Invoke-Row $row $S $paths $rd $hd $true 'WRONG' 'typed-user' $true
            Check 'row after a rejection is skipped' ($res3.Failed -eq 'skipped')
            Write-Host '6. Screenshot and mail text'
            Check 'screenshot PNG created' ($res.Shot -and (Test-Path $res.Shot) -and ([IO.File]::ReadAllBytes($res.Shot)[1] -eq 80)) 'System.Drawing may be unavailable'
            $tbl = @([pscustomobject]@{ Row = 1; TargetPSMPServer = 'psmp.test'; PSMPEnduser = 'typed-user'; TargetUser = 'root'; TargetServer = 'srv1'; Result = 'PASS'; FailedStep = ''; Reason = ''; ccp = 'skipped'; login = 'OK'; identity = 'OK'; hold = 'OK'; Seconds = 12; DetailLog = $res.Log; Screenshot = $res.Shot })
            $rep = Build-Report $tbl 'selftest' 'self-test'; Check 'report says ALL OK and embeds the picture' ($rep.Head -eq 'ALL OK (1 tests)' -and $rep.Html -like '*cid:shot1*')
        } finally { Remove-Item Env:PSMPH_FAKE_EXPECT, Env:PSMPH_FAKE_USER, Env:PSMPH_FAKE_MFA -ErrorAction SilentlyContinue; $Script:SshPath = '' }
    } finally { Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue }
    Write-Host ''; if ($Script:SelfFail) { Write-Host "$($Script:SelfFail) of $($Script:SelfTotal) checks FAILED" -ForegroundColor Red; return 1 } else { Write-Host "ALL $($Script:SelfTotal) CHECKS OK" -ForegroundColor Green; return 0 }
}

# ------------------------------------------------------------------ main
if ($Version) { Write-Host "psmphealth (PowerShell) $Script:Ver"; return }
if ($SelfTest) { $code = Invoke-SelfTest; exit $code }

if (-not $EnvName) {
    $names = @(Get-ChildItem -LiteralPath (Join-Path $Script:Root 'envs') -Directory | Where-Object { $_.Name -ne 'example' } | ForEach-Object { $_.Name })
    if ($names.Count -eq 1) { $EnvName = $names[0] } else { throw 'no environment selected: use -Env <name> (folders under envs\, besides example)' }
}
if ($EnvName -notmatch '^[A-Za-z0-9_-]{1,32}$') { throw "environment name '$EnvName' not allowed (letters, digits, _ -)" }
$base = Join-Path (Join-Path $Script:Root 'envs') $EnvName
$conf = Join-Path $base 'env.json'
if (-not (Test-Path -LiteralPath $conf)) { throw "environment '$EnvName' not found: $conf (the folder must be directly under envs\ and hold env.json and tests.csv)" }
$S = Get-Content -LiteralPath $conf -Raw -Encoding UTF8 | ConvertFrom-Json
$paths = @{ base = $base; tests = (Join-Path $base 'tests.csv'); logs = (Join-Path $base 'logs'); results = (Join-Path $base 'results'); known_hosts = (Join-Path $base 'known_hosts') }
foreach ($k in 'logs', 'results') { New-Item -ItemType Directory -Force -Path $paths[$k] | Out-Null }
$reason = [string](Get-Setting $S 'test.reason' 'automated psmp health test')
if ($reason -notmatch $Script:SafeValue) { throw 'test.reason in env.json contains characters that are not allowed' }
$csvPath = $Csv; if (-not $csvPath) { $csvPath = $paths.tests }
$rows = @(Read-Rows $csvPath (Get-Defaults $S) ([bool]$Manual))
if ($Only) { $keep = @($Only.Split(',') | ForEach-Object { [int]$_.Trim() }); $rows = @($rows | Where-Object { $keep -contains $_.N }) }
$mail = Get-Setting $S 'mail' $null

if ($DryRun) { foreach ($r in $rows) { $e = ''; if ($r.Err) { $e = $r.Err } else { $e = 'ok' }; Write-Host "$($r.N) $e" ($r.V | ConvertTo-Json -Compress) }; return }

if ($Validate) {
    Write-Host "psmphealth $Script:Ver  environment: $EnvName  tests: $csvPath"; $bad = 0
    function Line([bool]$Ok, [string]$What, [string]$Extra = '') { $s = 'ok'; if (-not $Ok) { $s = 'FAIL'; $script:bad++ }; Write-Host ("  [{0}] {1}{2}" -f $s, $What, $(if ($Extra) { " - $Extra" } else { '' })) }
    Write-Host 'Tools'; $sshc = Get-Command ssh.exe -ErrorAction SilentlyContinue; Line ([bool]$sshc) 'ssh.exe (OpenSSH client)' $(if ($sshc) { $sshc.Source } else { 'install the Windows optional feature "OpenSSH Client"' })
    Write-Host 'Test rows'; foreach ($r in $rows) { Line (-not $r.Err) "row $($r.N) $($r.V.Psmp) -> $($r.V.TUser)@$($r.V.THost)" $r.Err }
    $okrows = @($rows | Where-Object { $_.Enabled -and -not $_.Err })
    Write-Host 'PSMP servers (DNS + TCP port)'
    foreach ($k in @($okrows | ForEach-Object { "$($_.V.Psmp)|$($_.V.Port)" } | Sort-Object -Unique)) { $p = $k.Split('|'); $c = Test-PsmpHost $p[0] $p[1]; Line $c[0] "$($p[0])" $c[1] }
    Write-Host 'CCP (reachable, no logon)'
    if ($Manual) { Write-Host '  skipped (-Manual: the password is typed, CCP is not used)' }
    else { foreach ($u in @($okrows | ForEach-Object { $_.V.CcpUrl } | Sort-Object -Unique)) { $c = Test-Http $u; Line ($c -ne 0) $u $(if ($c) { "http $c" } else { 'no answer' }) } }
    Write-Host 'Files'; try { $t = Join-Path $base '.w'; Set-Content $t 'x'; Remove-Item $t; Line $true 'environment folder writable' } catch { Line $false 'environment folder writable' $_.Exception.Message }
    if ($mail -and $mail.smtp_host) { Write-Host 'Mail'; $mp = 25; if ($mail.smtp_port) { $mp = [int]$mail.smtp_port }; Line (Test-Tcp $mail.smtp_host $mp) "$($mail.smtp_host):$mp" ('to ' + (@($mail.to) -join ', ')) }
    Write-Host ''; if ($bad) { Write-Host "$bad PROBLEM(S) FOUND" } else { Write-Host 'ALL CHECKS PASSED' }
    if ($bad) { exit 1 } else { exit 0 }
}

# ---- real run
$mUser = ''; $mPw = ''
if ($Manual) {
    if ([Console]::IsInputRedirected) { throw '-Manual needs a terminal to type the user name and password (it cannot be piped or scheduled)' }
    $mUser = (Read-Host 'End user name (used for all rows)').Trim()
    if (-not $mUser -or $mUser -match ' ' -or $mUser -notmatch $Script:SafeValue) { throw 'end user name is empty or has characters that are not allowed (letters, digits and . _ : @ / - only) - not starting' }
    $sec = Read-Host "Password for $mUser (hidden, not stored)" -AsSecureString; $mPw = ConvertTo-Plain $sec
    if (-not $mPw) { throw 'empty password - not starting' }
}
$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path (Join-Path $paths.logs 'runs') $runId; New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$helperDir = Join-Path ([IO.Path]::GetTempPath()) ('psmph-' + [guid]::NewGuid().ToString('N').Substring(0, 10)); New-Helper $helperDir
$started = Get-Date; $results = @(); $rejected = $false
try {
    foreach ($row in @($rows | Where-Object { $_.Enabled })) {
        Write-Host ("[{0:HH:mm:ss}] row {1}: {2} -> {3}@{4} ..." -f (Get-Date), $row.N, $row.V.Psmp, $row.V.TUser, $row.V.THost)
        $res = Invoke-Row $row $S $paths $runDir $helperDir ([bool]$Manual) $mPw $mUser $rejected
        if ($res.Rejected) { $rejected = $true }
        $u = $row.V.User; if ($Manual) { $u = $mUser }
        $results += [pscustomobject][ordered]@{ TargetPSMPServer = $row.V.Psmp; PSMPPort = $row.V.Port; PSMPEnduser = $u; TargetUser = $row.V.TUser; TargetServer = $row.V.THost
            RunId = $runId; Row = $row.N; Result = $res.Result; FailedStep = $res.Failed; Reason = $res.Reason; ccp = $res.Steps.ccp; login = $res.Steps.login; identity = $res.Steps.identity; hold = $res.Steps.hold
            GapSec = $res.Gap; Seconds = $res.Secs; Attempts = $res.Attempts; DetailLog = $res.Log; Screenshot = $res.Shot }
        $extra = ''; if ($res.Result -ne 'PASS') { $extra = " at step $($res.Failed)" }
        Write-Host ("[{0:HH:mm:ss}] row {1} -> {2}{3} ({4}s)" -f (Get-Date), $row.N, $res.Result, $extra, $res.Secs)
    }
} finally { $mPw = $null; Remove-Item -Recurse -Force -LiteralPath $helperDir -ErrorAction SilentlyContinue }
$csvOut = Join-Path $paths.results "psmp-results-$runId.csv"
$results | Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding UTF8
$nfail = @($results | Where-Object { $_.Result -ne 'PASS' }).Count; $npass = $results.Count - $nfail
Write-Host "`nRESULTS: $npass PASS, $nfail FAIL  ->  $csvOut"
if ($NoMail -or -not $mail -or -not $mail.smtp_host -or -not $mail.to) { Write-Host ('mail: not sent' + $(if ($NoMail) { ' (-NoMail)' } else { ' (mail settings incomplete)' })); if ($nfail) { exit 1 } else { exit 0 } }
$sendOn = ([string](Get-Setting $mail 'send_on' 'failure')).ToLower()
if ($sendOn -eq 'always' -or $nfail -gt 0) {
    $note = "psmphealth (PowerShell) $Script:Ver / environment $EnvName"; if ($Manual) { $note += ' / credentials: MANUAL password (CCP skipped)' }
    $rep = Build-Report $results $runId $note
    $pre = [string](Get-Setting $mail 'subject_prefix' '[PSMP health]')
    try { Send-Report $mail "$pre $($rep.Head) - run $runId" $rep $results $csvOut; Write-Host 'mail: sent' }
    catch { Write-Host "WARNING: mail could not be sent: $($_.Exception.Message)" }
} else { Write-Host 'mail: nothing to report (send_on = failure and all tests passed)' }
if ($nfail) { exit 1 } else { exit 0 }
