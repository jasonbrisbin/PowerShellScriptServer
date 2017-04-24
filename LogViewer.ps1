import-module \\pdnas01\Infrastructure\Scripts\Modules\RCIS-Command.psm1
$host.UI.RawUI.BufferSize.Width=250
$log_selected=get-childitem $PSScriptRoot\Logs -Filter *.txt | Sort-Object LastWriteTime | select -First 1
#$log_selected=Show-rMenu -Title "Log File Viewer" -InputObject $log_list -Display Name -PageSize 10
get-content $log_selected.fullname -Wait