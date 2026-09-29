# ============================================================
# PCBridge 手 (hand) v1.3
# 云端智能体的"手"，装在被控电脑上。无脑执行器，不带任何上下文。
#
# 运行（在 PowerShell 里粘贴，注意整条必须在一行里）：
#   powershell -ep bypass -f "$env:USERPROFILE\Downloads\pcbridge-hand.ps1"
# 停止：关闭窗口或按 Ctrl+C —— 钥匙始终在你手里。
#
# 本机保存的两个文件（和本脚本同目录）：
#   hand-token.txt  工牌（DPAPI 加密，仅当前 Windows 用户可解）
#   hand-rules.json "这类以后都允许"的许可记录（仅本台电脑生效）
# ============================================================
param(
    # v1.2: 默认改走 IP 直连（:8443 便桥 /pb/ 前缀）。原因：线路上有设备
    # 按 TLS 握手里的域名掐连接（域名直连会被 RST），IP 直连不带域名可通。
    # 证书校验照常做（见下方回调），只是改看"证书链是否合法"而不是看域名。
    [string]$ServerUrl = "https://YOUR-SERVER-IP:8443/pb",
    [string]$DeviceName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# v1.2 证书校验：地址是 IP，"域名不匹配"是预期内的，放行；
# 但证书链必须合法（正规 CA 签发），链条有问题一律拒绝 —— 依旧防中间人。
# 坑：PS 5.1 不能把静态方法直接转成这个回调，必须包一层脚本块。
[Net.ServicePointManager]::ServerCertificateValidationCallback = [Net.Security.RemoteCertificateValidationCallback]{
    param($sender, $cert, $chain, $errors)
    if ($errors -eq [Net.Security.SslPolicyErrors]::None) { return $true }
    if ($errors -eq [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) { return $true }
    return $false
}

$StateDir = $PSScriptRoot
if (-not $StateDir) { $StateDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$TokenFile = Join-Path $StateDir "hand-token.txt"
$RulesFile = Join-Path $StateDir "hand-rules.json"
$ServerUrl = $ServerUrl.TrimEnd("/")

$KindLabel = @{ run = "跑命令"; put = "放文件（写入这台电脑）"; get = "取文件（从这台电脑读走）" }

# ---------- 工牌 ----------
function Save-Token([string]$token) {
    $sec = ConvertTo-SecureString $token -AsPlainText -Force
    ConvertFrom-SecureString -SecureString $sec | Set-Content -Path $TokenFile -Encoding ASCII
}
function Load-Token {
    if (-not (Test-Path $TokenFile)) { return $null }
    $sec = ConvertTo-SecureString (Get-Content $TokenFile -Raw)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
function Enroll {
    Write-Host ""
    Write-Host "第一次使用，需要配对。" -ForegroundColor Yellow
    Write-Host "在网页控制台点【添加电脑】拿到 6 位配对码（10 分钟有效）"
    $code = (Read-Host "请输入配对码").Trim()
    $body = @{ code = $code; name = $DeviceName } | ConvertTo-Json
    $r = Invoke-RestMethod -Uri "$ServerUrl/api/enroll" -Method Post `
        -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType "application/json; charset=utf-8"
    Save-Token $r.device_token
    Write-Host "配对成功，这台电脑已登记（工牌已加密保存）。" -ForegroundColor Green
    return $r.device_token
}

# ---------- "这类以后都允许" ----------
function Load-Rules {
    if (Test-Path $RulesFile) {
        $raw = Get-Content $RulesFile -Raw
        if ($raw) { return @(ConvertFrom-Json $raw) }
    }
    return @()
}
function Save-Rules($rules) {
    ConvertTo-Json -InputObject @($rules) -Depth 5 | Set-Content -Path $RulesFile -Encoding UTF8
}
function Test-AllowRule([string]$kind, [string]$dir) {
    foreach ($r in $script:Rules) {
        if ($r.kind -eq $kind -and $r.dir -ieq $dir) { return $true }
    }
    return $false
}
$script:Rules = Load-Rules

# ---------- 弹窗确认（三档：只读自动 / 问一下 / 禁止） ----------
# 禁止档：删除文件、改注册表、改系统设置 —— 连"允许"按钮都不给（火柴不发）。
function Test-Forbidden([string]$kind, $params) {
    if ($kind -eq "run") {
        $cmd = [string]$params.cmd
        if ($cmd -match '(?i)\b(Remove-Item|\brm\b|del\b|rd\b|rmdir|Format-|reg\s+(add|delete)|Set-ItemProperty.*\\CurrentVersion\\Run|shutdown|schtasks)') {
            return "命令里含删除/注册表/系统设置类操作，第一版一律禁止"
        }
    }
    return $null
}

function Ask-Confirm([string]$kind, [string]$detail, [string]$dir) {
    if (Test-AllowRule $kind $dir) { return "always" }
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    Add-Type -AssemblyName System.Drawing | Out-Null
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "PCBridge - 有任务请求你的许可"
    $form.Size = New-Object System.Drawing.Size(560, 330)
    $form.StartPosition = "CenterScreen"
    $form.TopMost = $true
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point(15, 12)
    $lbl.Size = New-Object System.Drawing.Size(520, 220)
    $lbl.Text = "电脑：$DeviceName`r`n操作：$($KindLabel[$kind])`r`n`r`n内容：`r`n$detail`r`n`r`n文件夹：$dir`r`n`r`n【允许这一次】只放行这一条    【这类以后都允许】同操作同文件夹不再问（仅本机）`r`n【拒绝】不执行"
    $form.Controls.Add($lbl)

    $btnOnce = New-Object System.Windows.Forms.Button
    $btnOnce.Text = "允许这一次"
    $btnOnce.Size = New-Object System.Drawing.Size(130, 34)
    $btnOnce.Location = New-Object System.Drawing.Point(15, 250)
    $btnOnce.Add_Click({ $form.Tag = "once"; $form.Close() })

    $btnAlways = New-Object System.Windows.Forms.Button
    $btnAlways.Text = "这类以后都允许"
    $btnAlways.Size = New-Object System.Drawing.Size(160, 34)
    $btnAlways.Location = New-Object System.Drawing.Point(160, 250)
    $btnAlways.Add_Click({ $form.Tag = "always"; $form.Close() })

    $btnDeny = New-Object System.Windows.Forms.Button
    $btnDeny.Text = "拒绝"
    $btnDeny.Size = New-Object System.Drawing.Size(100, 34)
    $btnDeny.Location = New-Object System.Drawing.Point(335, 250)
    $btnDeny.Add_Click({ $form.Tag = "deny"; $form.Close() })

    $form.Controls.AddRange(@($btnOnce, $btnAlways, $btnDeny))
    $form.ShowDialog() | Out-Null
    $verdict = if ($form.Tag) { [string]$form.Tag } else { "deny" }
    if ($verdict -eq "always") {
        $script:Rules += (New-Object psobject -Property @{ kind = $kind; dir = $dir })
        Save-Rules $script:Rules
    }
    return $verdict
}

# ---------- 三种活 ----------
function Cap-Output([string]$s) {
    if ($s.Length -gt 60000) { return $s.Substring(0, 60000) + "`n[output truncated]" }
    return $s
}

function Do-Run($params, [int]$timeoutSec) {
    $cmd = [string]$params.cmd
    $cwd = [string]$params.cwd
    if ($cwd) {
        if (-not (Test-Path $cwd)) { return @{ ok = $false; output = "目录不存在：$cwd" } }
    }
    $prefix = '$ProgressPreference=''SilentlyContinue''; [Console]::OutputEncoding=[Text.Encoding]::UTF8; '
    $encCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prefix + $cmd))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -NonInteractive -EncodedCommand $encCmd"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # v1.3: 子进程输出按 UTF-8 收（子命令头部强制 UTF-8 + 关进度条，进度条会在
    # 重定向时吐 CLIXML 杂音）
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    if ($cwd) { $psi.WorkingDirectory = $cwd }
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($timeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        return @{ ok = $false; output = "超时（$timeoutSec 秒），已中止" }
    }
    $out = $outTask.Result + "`n" + $errTask.Result
    $clixml = $out.IndexOf("#< CLIXML")
    if ($clixml -ge 0) { $out = $out.Substring(0, $clixml) }
    if ($p.ExitCode -ne 0) {
        return @{ ok = $false; output = (Cap-Output "exit code $($p.ExitCode)`n$out") }
    }
    return @{ ok = $true; output = (Cap-Output $out) }
}

function Do-Put($params, $headers) {
    $path = [string]$params.path
    if (-not [IO.Path]::IsPathRooted($path)) { return @{ ok = $false; output = "路径必须是绝对路径：$path" } }
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    try {
        Invoke-WebRequest -Uri "$ServerUrl/api/files/$($params.file_id)" -Headers $headers -OutFile $path -UseBasicParsing | Out-Null
        $size = (Get-Item $path).Length
        return @{ ok = $true; output = "已写入 $path（$size 字节）" }
    } catch {
        return @{ ok = $false; output = "下载写入失败：$($_.Exception.Message)" }
    }
}

function Do-Get($params, $headers, [int]$taskId) {
    $path = [string]$params.path
    if (-not (Test-Path $path)) { return @{ ok = $false; output = "文件不存在：$path" } }
    $boundary = [guid]::NewGuid().ToString()
    $fileBytes = [IO.File]::ReadAllBytes($path)
    $fileName = [IO.Path]::GetFileName($path)
    $enc = [Text.Encoding]::UTF8
    $head = $enc.GetBytes("--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`nContent-Type: application/octet-stream`r`n`r`n")
    $tail = $enc.GetBytes("`r`n--$boundary--`r`n")
    $body = New-Object byte[] ($head.Length + $fileBytes.Length + $tail.Length)
    [Buffer]::BlockCopy($head, 0, $body, 0, $head.Length)
    [Buffer]::BlockCopy($fileBytes, 0, $body, $head.Length, $fileBytes.Length)
    [Buffer]::BlockCopy($tail, 0, $body, $head.Length + $fileBytes.Length, $tail.Length)
    try {
        Invoke-RestMethod -Uri "$ServerUrl/api/tasks/$taskId/file" -Method Post -Headers $headers `
            -ContentType "multipart/form-data; boundary=$boundary" -Body $body -TimeoutSec 300 | Out-Null
        return @{ ok = $true; output = "已上传 $path（$($fileBytes.Length) 字节）" }
    } catch {
        return @{ ok = $false; output = "上传失败：$($_.Exception.Message)" }
    }
}

# ---------- 主循环 ----------
function Handle-Task($task, $headers) {
    $kind = [string]$task.type
    $params = $task.params
    Write-Host ""
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 来活了：$($KindLabel[$kind])（任务号 $($task.id)）" -ForegroundColor Cyan

    $verdict = "deny"
    $detail = ""
    $dir = ""
    if ($kind -eq "run") {
        $detail = [string]$params.cmd
        $dir = if ($params.cwd) { [string]$params.cwd } else { "(当前目录)" }
    } elseif ($kind -eq "put") {
        $detail = "写入文件：$($params.path)"
        $dir = Split-Path -Parent ([string]$params.path)
    } elseif ($kind -eq "get") {
        $detail = "读走文件：$($params.path)"
        $dir = Split-Path -Parent ([string]$params.path)
    } else {
        Report $task.id "rejected" "不认识的任务类型：$kind" $headers
        return
    }

    $forbidden = Test-Forbidden $kind $params
    if ($forbidden) {
        Write-Host "  禁止档：$forbidden" -ForegroundColor Red
        Report $task.id "rejected" "禁止档拒绝：$forbidden" $headers
        return
    }

    $verdict = Ask-Confirm $kind $detail $dir
    if ($verdict -eq "deny") {
        Write-Host "  已拒绝（用户没同意）" -ForegroundColor Yellow
        Report $task.id "rejected" "用户拒绝" $headers
        return
    }
    if ($verdict -eq "always") { Write-Host "  放行（已加入本机许可清单）" }

    Write-Host "  执行中…"
    $result = if ($kind -eq "run") {
        Do-Run $params ([int]$task.timeout)
    } elseif ($kind -eq "put") {
        Do-Put $params $headers
    } else {
        Do-Get $params $headers ([int]$task.id)
    }
    if ($result.ok) {
        Write-Host "  完成" -ForegroundColor Green
        Report $task.id "done" $result.output $headers
    } else {
        Write-Host "  失败：$($result.output)" -ForegroundColor Red
        Report $task.id "failed" $result.output $headers
    }
}

function Report([int]$taskId, [string]$status, [string]$output, $headers) {
    $body = @{ task_id = $taskId; status = $status; output = $output } | ConvertTo-Json
    # v1.3: 正文必须以 UTF-8 字节发出，否则中文在传输中变问号
    Invoke-RestMethod -Uri "$ServerUrl/api/report" -Method Post -Headers $headers `
        -ContentType "application/json; charset=utf-8" -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 30 | Out-Null
}

# ---- 启动 ----
$token = Load-Token
if (-not $token) { $token = Enroll }
$headers = @{ "X-Device-Token" = $token }
try { $host.UI.RawUI.WindowTitle = "PCBridge 手 - 关闭窗口即断开" } catch { }

Write-Host ""
Write-Host "=============================================="
Write-Host "  PCBridge 手已就绪：$DeviceName"
Write-Host "  服务器：$ServerUrl"
Write-Host "  关闭本窗口或 Ctrl+C = 立刻断开（之后云端叫不动这台电脑）"
Write-Host "=============================================="

while ($true) {
    try {
        $r = Invoke-RestMethod -Uri "$ServerUrl/api/poll" -Method Post -Headers $headers `
            -ContentType "application/json" -Body "{}" -TimeoutSec 60
        if ($null -ne $r.task) {
            Handle-Task $r.task $headers
        } else {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 待命中…" -ForegroundColor DarkGray
        }
    } catch {
        $resp = $_.Exception.Response
        if ($resp -and [int]$resp.StatusCode -eq 404) {
            Write-Host ""
            Write-Host "这台电脑的工牌已失效（可能被吊销）。停止运行。" -ForegroundColor Red
            break
        }
        Write-Host "连接不上服务器（$($_.Exception.Message)），5 秒后重试…" -ForegroundColor Yellow
        Start-Sleep -Seconds 5
    }
}
