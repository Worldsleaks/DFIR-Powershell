##########################################################################################
#                                   ODIN - A DFIR ENDGAME                                #
#   Coded by Worldsleaks                                                                 #
#   Version: 1.0                                                                         #
#   Description: Extracts forensics artifacts in csv format in Windows endpoints         #
##########################################################################################


$Version = '1.0'
$ASCIIBanner = @"                                                                                                                                                              
                   -                                            ####             ####               
                 #####                                          ####             ###                
                ########                                         ###             ###                
              ####    ###          ##                    #       ###             ###                
            ####        ###        ####+               ###       ###             ###                
          ####            ###      #######          ######       ###       ###   +##                
         ####             ####     #########      ####  ##       ###      -##### ###                
           ####         -###       ###   ##### ####+    ##       ###          ######                
             ####      ###         ###      #####       ##       ###            #####               
               ####+ ###           ###     ########     ##       ###             ######             
                 ######            ###   ###    .####   ##       ###             #########          
                 ######            #######         #######       ###             ###   ###.         
               #### #####          ####-              ####       ###             ###                
             ####-    #####        ##                   ##      +###             ###                
           #####        #####                                   ####             ###.               
          ####            ####                                  ####             ####               
                                                                ####             ####  `n
"@
Write-Host $ASCIIBanner -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "Coded by Worldsleaks" -ForegroundColor Cyan
Write-Host "===================================================================================================`n" -ForegroundColor Green

# Give color points to output results
function Get-Dots {
    Write-Host "[+]" -ForegroundColor Cyan -NoNewline
}

# Zip evidences and delete working directory
function ConvertTo-Zip {
    param (
        [string]$folderPath
    )
    Write-Host "$(Get-Dots) Compressing evidences..."
    # Zip evidences stored in output directory
    Add-Log -message "[+] $(Get-CurrentTime) - Started to compress evidences in: $folderPath.zip" -path "$folderPath"
    Compress-Archive -Force -LiteralPath $folderPath -DestinationPath "$folderPath.zip"
    Write-Host "$(Get-Dots) Evidences compressed in: $folderPath.zip"
    
    # Remove the output directory once the evidences are compressed
    Remove-Item -LiteralPath $folderPath -Force -Recurse
    if ($? -eq $true) {
        Write-Host "$(Get-Dots) Output directory deleted"
        Write-Host "$(Get-Dots) Exiting..."
    } else {
        Write-Host "$(Get-Dots) Failed to delete the output directory!"
    }
}

# Add info to log file
function Add-Log {
    param (
        [string]$message,
        [string]$path
    )
    Add-Content -Path "$path\Odin.log" -Value "$message"
}

# Get Current time for logging
function Get-CurrentTime {
    Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
}

function Check-Execution {
    param (
        [string]$result,
        [string]$artifact
    )
    if ($result -eq $false) {
        Write-Host " - " -NoNewline
        Write-Host "Failed" -ForegroundColor Red
        Add-Log -message "[+] $(Get-CurrentTime) - $artifact couldn't be copied!!" -path $path
    } else {
        Write-Host " - " -NoNewline
        Write-Host "OK" -ForegroundColor Green
        Add-Log -message "[+] $(Get-CurrentTime) - $artifact copied OK" -path $path
    }
}

# Extracts information about the status and configuration of the endpoint
function Get-System {
    param (
        [string]$path
    )
    # Creates System information directory
    New-Item -Path "$path" -Name "System Information" -ItemType Directory -Force | Out-Null
    Write-Host "$(Get-Dots) System Information directory created: $path\System Information"; Add-Log -message "[+] $(Get-CurrentTime) - System Information directory created: $path\System Information" -path $path
    Add-Log -message "[+] $(Get-CurrentTime) - Starting to extract system artifacts from the endpoint..." -path $path
    # Computer Info
    Write-Host "$(Get-Dots) Obtaining Computer Information" -NoNewline
    Get-ComputerInfo >> "$path\System Information\ComputerInfo.txt" ; Check-Execution -result $? -artifact "Computer information"
    # NetIPConfiguration
    Write-Host "$(Get-Dots) Obtaining Network Configuration" -NoNewline
    Get-NetIPConfiguration >> "$path\System Information\NetIPConfiguration.txt" ; Check-Execution -result $? -artifact "Network configuration"
    # Active connections
    Write-Host "$(Get-Dots) Obtaining active network connections" -NoNewline
    Get-NetTCPConnection >> "$path\System Information\Active Connections.txt" ; Check-Execution -result $? -artifact "Active connections"
    # Firewall Rules
    Write-Host "$(Get-Dots) Searching for firewall rules" -NoNewline
    Get-NetFirewallRule -ErrorAction SilentlyContinue >> "$path\System Information\Firewall Rules.txt" ; Check-Execution -result $? -artifact "Firewall rules"
    # IP Address
    Write-Host "$(Get-Dots) Obtaining Network Information" -NoNewline
    Get-NetIPAddress >> "$path\System Information\IPAddresses.txt" ; Check-Execution -result $? -artifact "Firewall rules"
    # Running processes 
    Write-Host "$(Get-Dots) Obtaining running processes" -NoNewline
    Get-Process >> "$path\System Information\Running Processes.txt" ; Check-Execution -result $? -artifact "Running processes"
    # Network Shares
    Write-Host "$(Get-Dots) Obtaining network shares" -NoNewline
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ >> "$path\System Information\Network Shares.txt" ; Check-Execution -result $? -artifact "Network shares"
    # SMB Shares
    Write-Host "$(Get-Dots) Obtaining SMB shares" -NoNewline
    Get-SmbShare >> "$path\System Information\SMB Shares.txt" ; Check-Execution -result $? -artifact "SMB shares"
    # RDP Sessions
    Write-Host "$(Get-Dots) Looking for RDP Sessions" -NoNewline
    qwinsta /server:localhost >> "$path\System Information\RDP Sessions.txt" ; Check-Execution -result $? -artifact "RDP sessions"
    # Running Services
    Write-Host "$(Get-Dots) Looking for running services" -NoNewline
    Get-Service | Select-Object Name, DisplayName, Status | Format-Table -AutoSize >> "$path\System Information\Running Services.txt" ; Check-Execution -result $? -artifact "Running services"
    # Installed Programs
    Write-Host "$(Get-Dots) Checking installed programs" -NoNewline 
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Format-Table -AutoSize >> "$path\System Information\Installed Programs.txt" ; Check-Execution -result $? -artifact "Installed programs"
    # Schedule Tasks
    Write-Host "$(Get-Dots) Obtaining scheduled tasks" -NoNewline
    Get-ScheduledTask | Select-Object Actions, Author, TaskName, TaskPath, URI, Triggers >> "$path\System Information\Scheduled Tasks.txt" ; Check-Execution -result $? -artifact "Scheduled tasks"
    # Active users / Kerberos Sessions
    Write-Host "$(Get-Dots) Obtaining active users / Kerberos sessions" -NoNewline
    query user /server:$server >> "$path\System Information\Active Users.txt" ; Check-Execution -result $? -artifact "Active users"
    # Administrator users
    Write-Host "$(Get-Dots) Looking for administrator users" -NoNewline
    $language = (Get-WinSystemLocale).Name; if ($language -match 'es-') { $adminGroupName = "Administradores" } else { $adminGroupName = "Administrators" }; $adminGroupMembers = Get-LocalGroupMember -Group $adminGroupName | Select-Object Name, ObjectClass; $outputPath = "$path\System Information\Administrator Users.txt"; $adminGroupMembers | Out-File -FilePath $outputPath -Encoding utf8; Check-Execution -result $? -artifact "Administrator users"
    # Local users
    Write-Host "$(Get-Dots) Detecting local users" -NoNewline
    Get-LocalUser | Format-Table >> "$path\System Information\Active Users.txt" ; Check-Execution -result $? -artifact "Active users"
    # Process CommandLine
    Write-Host "$(Get-Dots) Searching for process command lines" -NoNewline
    Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine, Path | Format-List >> "$path\System Information\Processes CommandLines.txt" ; Check-Execution -result $? -artifact "Processes commandlines"
    # Powershell History
    Write-Host "$(Get-Dots) Extracting Powershell history" -NoNewline
    Get-History >> "$path\System Information\Powershell History.txt" ; Check-Execution -result $? -artifact "Powershell history"
    # Recently installed softw 
    Write-Host "$(Get-Dots) Extracting recently installed software" -NoNewline
    Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Format-List * >> "$path\System Information\Recently Installed Software.txt" ; Check-Execution -result $? -artifact "Recently installed software"
}

# Get Application, System and Security
function Get-WindowsLogs {
    param (
        [string]$path
    )
    # Creates Windows Event Logs directory
    New-Item -Path "$path" -Name "Windows Event Log" -ItemType Directory -Force | Out-Null
    Write-Host "$(Get-Dots) Windows Event Log directory created: $path\Windows Event Log"; Add-Log -message "[+] $(Get-CurrentTime) - Windows Event Log directory created OK" -path $path
    # Define what Windows Event Log to extract:
    $logs = 'Application', 'System', 'Security'
    $allEntries = @()
    # Extracts last 7 days
    $startDate = (Get-Date).AddDays(-7)
    foreach ($artifact in $logs) {
        # Add info to output
        Write-Host "$(Get-Dots) Starting to extract $artifact artifact..."
        # Add info to log
        Add-Log -message "[+] $(Get-CurrentTime) - Starting to extract $artifact artifact..." -path $path
        
        # Export events to .evtx file
        $evtxPath = "$path\Windows Event Log\$artifact.evtx"
        wevtutil epl $artifact $evtxPath
        Write-Host "$(Get-Dots) $artifact events exported to $evtxPath"
        Add-Log -message "[+] $(Get-CurrentTime) - $artifact events exported to $evtxPath" -path $path

        # Get events per artifact
        $entries = Get-WinEvent -FilterHashtable @{LogName=$artifact; StartTime=$startDate} | Select-Object TimeCreated, Id, LevelDisplayName, Message
        $allEntries += $entries

        # Export all events to csv file
        $csvPath = "$path\Windows Event Log\AllEvents.csv"
        $allEntries | Export-Csv -Path $csvPath -NoTypeInformation
    }
    Write-Host "$(Get-Dots) All events exported to $csvPath"
    Add-Log -message "[+] $(Get-CurrentTime) - All events exported to $csvPath" -path $path
}



# Check for Administrator privileges
$isAdmin = [bool](New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "$(Get-Dots) Session with administrator privileges created"
} else {
    Write-Host "$(Get-Dots) No administrator privileges detected. Use administrator privileges for the extraction of all artifacts!!"
    Write-Host "$(Get-Dots) Non administrator session created..."
}

Write-Host "$(Get-Dots) Creating output directory..."
$CurrentPath = $pwd
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$WorkingFolder = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"
mkdir -Force $WorkingFolder | Out-Null
Write-Host "$(Get-Dots) Output directory created: $WorkingFolder"
Add-Log -message "[+] $(Get-CurrentTime) - Output directory created - $WorkingFolder" -path $WorkingFolder

# Detects current user and SID
$currentUsername = (Get-WmiObject Win32_Process -f 'Name="explorer.exe"').GetOwner().User
$currentUserSid = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match 'S-1-5-21-\d+-\d+\-\d+\-\d+$' -and $_.ProfileImagePath -match "\\$currentUsername$"} | ForEach-Object{$_.PSChildName}
Write-Host "$(Get-Dots) Current user detected: $currentUsername ($currentUserSid)"
Add-Log -message "[+] $(Get-CurrentTime) - Current user detected: $currentUsername ($currentUserSid)" -path $WorkingFolder
# Log if current user has admin privs
if ($isAdmin) {
    Add-Log -message "[+] $(Get-CurrentTime) - Current user has Administrator rights" -path $WorkingFolder
} else {
    Add-Log -message "[+] $(Get-CurrentTime) - Current user doesn't have Administrator rights" -path $WorkingFolder
}


function Invoke-WithoutAdminPrivilege {
    Get-System -path $WorkingFolder
}

function Invoke-WithAdminPrivilege {
    Get-WindowsLogs -path $WorkingFolder
}

Invoke-WithoutAdminPrivilege
if ($isAdmin) {
    Invoke-WithAdminPrivilege
}

ConvertTo-Zip -folderPath $WorkingFolder
