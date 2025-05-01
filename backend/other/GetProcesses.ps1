# Get the current username
$username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Get processes owned by the current user
$processes = Get-Process -IncludeUserName | Where-Object { $_.UserName -eq $username }

# Display PID and Process Name for each process
$processes | Select-Object Id, ProcessName | Format-Table -AutoSize