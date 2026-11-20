# -*- coding: utf-8 -*-
"""R1 §5.1：本机窗口授权（Windows PowerShell + System.Windows.Forms）。

父进程把完整候选 JSON 以 Base64 嵌入 -EncodedCommand；子进程只回候选序号，
父进程按序号回原候选表取身份。窗口默认不选中，保护项禁选；60 秒超时/取消/
关窗/非交互均未授权。不提供全选、记住、不再询问。
"""

import base64
import json

import port_console as pc


def _ps_quote_single(text: str) -> str:
    return text.replace("'", "''")


def _build_script(candidates: list, timeout_seconds: int = 60) -> str:
    cand_json = json.dumps(candidates, ensure_ascii=False, separators=(",", ":"))
    cand_b64 = base64.b64encode(cand_json.encode("utf-8")).decode("ascii")
    # Base64 只含 A-Za-z0-9+/=，单引号安全；仍做一次单引号转义防御。
    b64 = _ps_quote_single(cand_b64)
    return r"""
$ErrorActionPreference = 'Stop'
$status = 'unavailable'
$index = -1
$message = ''
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    if (-not [Environment]::UserInteractive -or
        -not [System.Windows.Forms.SystemInformation]::UserInteractive) {
        $message = '当前无交互桌面'
    } else {
        $candJson = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String('__CAND_B64__'))
        $candidates = @($candJson | ConvertFrom-Json)
        $script:selected = -1
        $script:timedOut = $false

        $form = New-Object System.Windows.Forms.Form
        $form.Text = '端口扳手 1.4.2 - 本机授权'
        $form.StartPosition = 'CenterScreen'
        $form.FormBorderStyle = 'FixedDialog'
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.TopMost = $true
        $form.ClientSize = New-Object System.Drawing.Size(760, 430)

        $title = New-Object System.Windows.Forms.Label
        $title.Text = '端口有多个占用者。请选择要关闭的目标（默认不选；保护项禁选）。'
        $title.AutoSize = $false
        $title.Location = New-Object System.Drawing.Point(14, 12)
        $title.Size = New-Object System.Drawing.Size(730, 34)

        $list = New-Object System.Windows.Forms.ListBox
        $list.Location = New-Object System.Drawing.Point(14, 50)
        $list.Size = New-Object System.Drawing.Size(730, 130)
        $list.IntegralHeight = $false
        $list.SelectedIndex = -1

        for ($i = 0; $i -lt $candidates.Count; $i++) {
            $c = $candidates[$i]
            $prefix = ''
            if (-not [bool]$c.kill_allowed) { $prefix = '[禁选] ' }
            $line = '{0}端口 {1}  PID {2}  {3}  启动 {4}' -f $prefix, $c.port, $c.pid, $c.proc, $c.started
            [void]$list.Items.Add($line)
        }

        $details = New-Object System.Windows.Forms.Label
        $details.Location = New-Object System.Drawing.Point(14, 190)
        $details.Size = New-Object System.Drawing.Size(730, 150)
        $details.BorderStyle = 'FixedSingle'
        $details.Text = '未选择目标。'

        $ok = New-Object System.Windows.Forms.Button
        $ok.Text = '授权关闭'
        $ok.Location = New-Object System.Drawing.Point(560, 370)
        $ok.Size = New-Object System.Drawing.Size(90, 32)
        $ok.Enabled = $false

        $cancel = New-Object System.Windows.Forms.Button
        $cancel.Text = '取消'
        $cancel.Location = New-Object System.Drawing.Point(656, 370)
        $cancel.Size = New-Object System.Drawing.Size(88, 32)
        $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

        $list.Add_SelectedIndexChanged({
            $i = $list.SelectedIndex
            if ($i -ge 0) {
                $c = $candidates[$i]
                $script:selected = $i
                $killText = '不可关闭'
                if ([bool]$c.kill_allowed) { $killText = '可关闭' }
                $details.Text = (
                    'PID: ' + $c.pid + "`r`n" +
                    '进程: ' + $c.proc + "`r`n" +
                    '启动: ' + $c.started + "`r`n" +
                    '可执行: ' + $c.exe + "`r`n" +
                    '绑定地址: ' + ($c.addrs -join ', ') + "`r`n" +
                    '名称/级别: ' + $c.name + ' / ' + $c.level + "`r`n" +
                    '保护原因: ' + $c.protected_reason + "`r`n" +
                    '状态: ' + $killText
                )
                $ok.Enabled = [bool]$c.kill_allowed
            } else {
                $script:selected = -1
                $details.Text = '未选择目标。'
                $ok.Enabled = $false
            }
        })

        $ok.Add_Click({
            if ($script:selected -ge 0 -and [bool]$candidates[$script:selected].kill_allowed) {
                $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Close()
            }
        })

        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = __TIMEOUT_MS__
        $timer.Add_Tick({
            $script:timedOut = $true
            $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $form.Close()
        })
        $timer.Start()

        [void]$form.Controls.Add($title)
        [void]$form.Controls.Add($list)
        [void]$form.Controls.Add($details)
        [void]$form.Controls.Add($ok)
        [void]$form.Controls.Add($cancel)
        $form.AcceptButton = $ok
        $form.CancelButton = $cancel
        [void]$form.ShowDialog()
        $timer.Stop()

        if ($form.DialogResult -eq [System.Windows.Forms.DialogResult]::OK -and
            $script:selected -ge 0 -and
            [bool]$candidates[$script:selected].kill_allowed) {
            $status = 'selected'
            $index = $script:selected
        } elseif ($script:timedOut) {
            $status = 'timeout'
        } else {
            $status = 'cancelled'
        }
    }
} catch {
    $status = 'unavailable'
    $message = $_.Exception.Message
}
[pscustomobject]@{
    status = $status
    index = $index
    message = $message
} | ConvertTo-Json -Compress
""".replace("__CAND_B64__", b64).replace("__TIMEOUT_MS__", str(int(timeout_seconds * 1000)))


def ask_user(candidates: list, timeout: float = 60.0) -> tuple:
    """返回 (index, status)。status ∈ selected/cancelled/timeout/unavailable。

    只把候选序号回给父进程；父进程按原候选表取身份，不接受子进程回传新身份。
    """
    if not candidates:
        return -1, "unavailable"
    script = _build_script(candidates, int(timeout))
    try:
        out = pc.run_powershell(script, timeout=timeout + 5.0, sta=True)
    except pc.ScanError:
        return -1, "unavailable"
    payload = None
    for line in reversed([x.strip() for x in out.splitlines() if x.strip()]):
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            break
    if not isinstance(payload, dict):
        return -1, "unavailable"
    status = payload.get("status")
    if status not in ("selected", "cancelled", "timeout", "unavailable"):
        return -1, "unavailable"
    index = payload.get("index", -1)
    if status == "selected":
        if not isinstance(index, int) or isinstance(index, bool):
            return -1, "unavailable"
        if not (0 <= index < len(candidates)):
            return -1, "unavailable"
        if not candidates[index].get("kill_allowed"):
            return -1, "cancelled"
    else:
        index = -1
    return index, status
