# Windowed listening fixture (fixture_windowed.ps1)
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File fixture_windowed.ps1 -Port 46001 [-IgnoreCloseCount 1]
# Behavior: creates a visible WinForms window and a 127.0.0.1 TcpListener; prints READY when ready.
# It exits normally on WM_CLOSE. With -IgnoreCloseCount N, FormClosing cancels the first N close
# attempts to build the 428 force-confirmation path. Test-only: no file writes, no network except loopback.
param(
    [int]$Port = 46001,
    [int]$IgnoreCloseCount = 0
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'PortConsole Test Window'
$form.Size = New-Object System.Drawing.Size(360, 220)
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(40, 40)

$script:IgnoreLeft = $IgnoreCloseCount
$form.add_FormClosing({
    param($sender, $e)
    if ($script:IgnoreLeft -gt 0) {
        $script:IgnoreLeft = $script:IgnoreLeft - 1
        $e.Cancel = $true
    }
})

$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()

# Emit READY only after the listener has started and before the message loop.
# Do not use Add_Shown: Write-Output in event callbacks does not reach the stdout pipe.
Write-Output 'READY'

try {
    [System.Windows.Forms.Application]::Run($form)
}
finally {
    $listener.Stop()
}
