##########################################################################################
#                                   ODIN - A DFIR ENDGAME                                #
#   Coded by Worldsleaks                                                                 #
#   Version: 1.0                                                                         #
#   Description: Extracts forensics artifacts in csv format in Windows endpoints         #
##########################################################################################

# Clear possible previous failed attempts of ODIN execution
function Invoke-Clear {
    $CurrentPath = $pwd
    $ExecutionTime = $(get-date -f yyyy-MM-dd)
    $WorkingFolder = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"
    if (Test-Path $WorkingFolder) {
        Remove-Item -Path $WorkingFolder -Force -Recurse
    }
}

Invoke-Clear

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

function Invoke-InfoDot {
    Write-Host "[INFO]" -ForegroundColor Cyan -NoNewline
}

function Invoke-WarningDot {
    Write-Host "[WARN]" -ForegroundColor Yellow -NoNewline
}

function Invoke-CheckExecution {
    param (
        [string]$result,
        [string]$artifact,
        [string]$tab
    )
    if ($tab -eq "yes") {
        # Activated tab
        if ($result -eq $false) {
            Write-Host "    - [FAIL]" -ForegroundColor Red -NoNewline
            Add-Log -message " [FAIL] $(Get-CurrentTime) - $artifact couldn't be copied!!" -path $path
        } else {
            Write-Host "    - [OK]" -ForegroundColor Green -NoNewline
            Add-Log -message "[OK] $(Get-CurrentTime) - $artifact copied" -path $path
        }
    } else {
        # Non activated tab
        if ($result -eq $false) {
            Write-Host "[FAIL]" -ForegroundColor Red -NoNewline
            Add-Log -message "[FAIL] $(Get-CurrentTime) - $artifact couldn't be copied!!" -path $path
        } else {
            Write-Host "[OK]" -ForegroundColor Green -NoNewline
            Add-Log -message "[OK] $(Get-CurrentTime) - $artifact copied" -path $path
        }
    }
}

function Invoke-CheckExecutionAfterCompressing {
    param (
        [string]$result,
        [string]$folderpath
    )
    if ($result -eq $false) {
        Write-Host "[FAIL]" -ForegroundColor Red -NoNewline
        Write-Host " Evidences failed to compressed"
    } else {
        Write-Host "[OK]" -ForegroundColor Green -NoNewline
        Write-Host " Evidences compressed in: $folderPath.zip"
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

# Zip evidences and delete working directory
function ConvertTo-Zip {
    param (
        [string]$folderPath
    )
    Write-Host "$(Invoke-InfoDot) Compressing evidences..."
    # Zip evidences stored in output directory
    Add-Log -message "[INFO] $(Get-CurrentTime) - Started to compress evidences in: $folderPath.zip" -path "$folderPath"
    Compress-Archive -Force -LiteralPath $folderPath -DestinationPath "$folderPath.zip" ; Invoke-CheckExecutionAfterCompressing -result $? -folderpath $folderPath
    
    # Remove the output directory once the evidences are compressed
    Remove-Item -LiteralPath $folderPath -Force -Recurse
    if ($? -eq $true) {
        Write-Host "$(Invoke-InfoDot) Output directory deleted"
        Write-Host "$(Invoke-InfoDot) Exiting..."
    } else {
        Write-Host "$(Invoke-InfoDot) Failed to delete the output directory!"
    }
}

# Get Current time for logging
function Get-CurrentTime {
    Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
}

# Extracts information about the status and configuration of the endpoint
function Get-System {
    param (
        [string]$path
    )
    # Creates System information directory
    New-Item -Path "$path" -Name "System Information" -ItemType Directory -Force | Out-Null
    Add-Log -message "[INFO] $(Get-CurrentTime) - System Information directory created: $path\System Information" -path $path
    Add-Log -message "[INFO] $(Get-CurrentTime) - Starting to extract system artifacts from the endpoint..." -path $path
    
    Write-Host "$(Invoke-InfoDot) Starting to extract the characteristics of the environment..."

    # Computer Info
    Get-ComputerInfo >> "$path\System Information\ComputerInfo.txt" ; Invoke-CheckExecution -result $? -artifact "Computer information" -tab yes    
    Write-Host " Computer Information"
    
    # NetIPConfiguration
    Get-NetIPConfiguration >> "$path\System Information\NetIPConfiguration.txt" ; Invoke-CheckExecution -result $? -artifact "Network configuration" -tab yes
    Write-Host " Network Configuration"

    # Active connections
    Get-NetTCPConnection >> "$path\System Information\Active Connections.txt" ; Invoke-CheckExecution -result $? -artifact "Active connections" -tab yes
    Write-Host " Active network connections"  
    
    # Firewall Rules
    Get-NetFirewallRule -ErrorAction SilentlyContinue >> "$path\System Information\Firewall Rules.txt" ; Invoke-CheckExecution -result $? -artifact "Firewall rules" -tab yes
    Write-Host " Firewall rules"  
    
    # IP Address
    Get-NetIPAddress >> "$path\System Information\IPAddresses.txt" ; Invoke-CheckExecution -result $? -artifact "Firewall rules" -tab yes
    Write-Host " Network Information"  
    
    # Running processes  
    Get-Process >> "$path\System Information\Running Processes.txt" ; Invoke-CheckExecution -result $? -artifact "Running processes" -tab yes
    Write-Host " Running processes" 
    
    # Network Shares
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ >> "$path\System Information\Network Shares.txt" ; Invoke-CheckExecution -result $? -artifact "Network shares" -tab yes
    Write-Host " Network shares"  

    # SMB Shares
    Get-SmbShare >> "$path\System Information\SMB Shares.txt" ; Invoke-CheckExecution -result $? -artifact "SMB shares" -tab yes
    Write-Host " SMB shares"  

    # RDP Sessions
    qwinsta /server:localhost >> "$path\System Information\Open Sessions.txt" ; Invoke-CheckExecution -result $? -artifact "Open sessions" -tab yes
    Write-Host " Open Sessions"   

    # Running Services
    Get-Service | Select-Object Name, DisplayName, Status | Format-Table -AutoSize >> "$path\System Information\Running Services.txt" ; Invoke-CheckExecution -result $? -artifact "Running services" -tab yes
    Write-Host " Running services"  

    # Installed Programs
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Format-Table -AutoSize >> "$path\System Information\Installed Programs.txt" ; Invoke-CheckExecution -result $? -artifact "Installed programs" -tab yes
    Write-Host " Installed programs"   

    # Schedule Tasks
    Get-ScheduledTask | Select-Object Actions, Author, TaskName, TaskPath, URI, Triggers >> "$path\System Information\Scheduled Tasks.txt" ; Invoke-CheckExecution -result $? -artifact "Scheduled tasks" -tab yes
    Write-Host " Scheduled tasks"  

    # Administrator users
    $language = (Get-WinSystemLocale).Name; $adminGroupName = if ($language -match 'es-') { "Administradores" } else { "Administrators" }; $adminGroupMembers = Get-LocalGroupMember -Group $adminGroupName | Select-Object Name, ObjectClass; $outputPath = "$path\System Information\Administrator_Users.txt"; $adminGroupMembers | Out-File -FilePath $outputPath ; Invoke-CheckExecution -result $? -artifact "Administrator users" -tab yes
    Write-Host " Administrator users"  

    # Local users
    Get-LocalUser | Format-Table >> "$path\System Information\Local Users.txt" ; Invoke-CheckExecution -result $? -artifact "Active users" -tab yes
    Write-Host " Local users"  

    # Process CommandLine
    Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine, Path | Format-List >> "$path\System Information\Processes CommandLines.txt" ; Invoke-CheckExecution -result $? -artifact "Processes commandlines" -tab yes
    Write-Host " Process command lines"  

    # Powershell History
    Get-History >> "$path\System Information\Powershell History.txt" ; Invoke-CheckExecution -result $? -artifact "Powershell history" -tab yes
    Write-Host " Powershell history"  

    # Recently installed software
    Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Format-List * >> "$path\System Information\Recently Installed Software.txt" ; Invoke-CheckExecution -result $? -artifact "Recently installed software" -tab yes
    Write-Host " Recently installed software"  
}

# Get Application, System and Security
function Get-WindowsLogs {
    param (
        [string]$path
    )
    # Creates Windows Event Logs directory
    New-Item -Path "$path" -Name "Windows Event Log" -ItemType Directory -Force | Out-Null
    Add-Log -message "[INFO] $(Get-CurrentTime) - Windows Event Log directory created OK" -path $path
    # Define what Windows Event Log to extract:
    $logs = 'Application', 'System', 'Security'

    Write-Host "$(Invoke-InfoDot) Starting to extract Windows Event Log..."
    foreach ($artifact in $logs) {
        # Add info to log
        Add-Log -message "[INFO] $(Get-CurrentTime) - Starting to extract $artifact.evtx..." -path $path
        
        # Export events to .evtx file
        $evtxPath = "$path\Windows Event Log\$artifact.evtx"
        wevtutil epl $artifact $evtxPath ; Invoke-CheckExecution -result $? -artifact $artifact -tab yes
        Write-Host " $artifact.evtx"
    }
}


# Check for Administrator privileges
$isAdmin = [bool](New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "$(Invoke-InfoDot) Session with administrator privileges created"
} else {
    Write-Host "$(Invoke-WarningDot) No administrator privileges detected. Use administrator privileges for the extraction of all artifacts!!"
    Write-Host "$(Invoke-WarningDot) Non administrator session created..."
}

Write-Host "$(Invoke-InfoDot) Creating output directory..."
$CurrentPath = $pwd
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$WorkingFolder = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"
mkdir -Force $WorkingFolder | Out-Null
Write-Host "$(Invoke-InfoDot) Output directory created: $WorkingFolder"
Add-Log -message "[INFO] $(Get-CurrentTime) - Output directory created - $WorkingFolder" -path $WorkingFolder

# Detects current user and SID
$currentUsername = (Get-WmiObject Win32_Process -f 'Name="explorer.exe"').GetOwner().User
$currentUserSid = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match 'S-1-5-21-\d+-\d+\-\d+\-\d+$' -and $_.ProfileImagePath -match "\\$currentUsername$"} | ForEach-Object{$_.PSChildName}
Write-Host "$(Invoke-InfoDot) Current user detected: $currentUsername ($currentUserSid)"
Add-Log -message "[INFO] $(Get-CurrentTime) - Current user detected: $currentUsername ($currentUserSid)" -path $WorkingFolder
# Log if current user has admin privs
if ($isAdmin) {
    Add-Log -message "[INFO] $(Get-CurrentTime) - Current user has Administrator rights" -path $WorkingFolder
} else {
    Add-Log -message "[WARN] $(Get-CurrentTime) - Current user doesn't have Administrator rights" -path $WorkingFolder
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
