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

# Extracts information about the status and configuration of the endpoint
function Get-System {
    param (
        [string]$path
    )
    # Creates System information directory
    New-Item -Path "$path" -Name "System Information" -ItemType Directory -Force | Out-Null
    Write-Host "$(Get-Dots) System Information directory created: $path\System Information"; Add-Log -message "[+] $(Get-CurrentTime) - System Information directory created OK" -path $path
    Add-Log -message "[+] $(Get-CurrentTime) - Starting to extract system artifacts from the endpoint..." -path $path
    # Computer Info
    Write-Host "$(Get-Dots) Obtaining Computer Information..."
    Get-ComputerInfo >> "$path\System Information\ComputerInfo.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Computer information copied OK" -path $path
    # NetIPConfiguration
    Write-Host "$(Get-Dots) Obtaining Network Configuration..."
    Get-NetIPConfiguration >> "$path\System Information\NetIPConfiguration.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - IP configuration copied OK" -path $path
    # Active connections
    Write-Host "$(Get-Dots) Obtaining active network connections..."
    Get-NetTCPConnection >> "$path\System Information\Active Connections.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Active connections copied OK" -path $path
    # Firewall Rules
    Write-Host "$(Get-Dots) Searching for firewall rules..."
    Get-NetFirewallRule >> "$path\System Information\Firewall Rules.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Firewalls rules copied OK" -path $path
    # IP Address
    Write-Host "$(Get-Dots) Obtaining Network Information..."
    Get-NetIPAddress >> "$path\System Information\IPAddresses.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - IP address information copied OK" -path $path
    # Running processes 
    Write-Host "$(Get-Dots) Obtaining running processes..."
    Get-Process >> "$path\System Information\Running Processes.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Running processes copied OK" -path $path
    # Network Shares
    Write-Host "$(Get-Dots) Obtaining network shares..."
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ >> "$path\System Information\Network Shares.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Network shares copied OK" -path $path
    # SMB Shares
    Write-Host "$(Get-Dots) Obtaining SMB shares..."
    Get-SmbShare >> "$path\System Information\SMB Shares.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - SMB Shares copied OK" -path $path
    # RDP Sessions
    Write-Host "$(Get-Dots) Looking for RDP Sessions..."
    qwinsta /server:localhost >> "$path\System Information\RDP Sessions.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - RDP Sessions copied OK" -path $path
    # Running Services
    Write-Host "$(Get-Dots) Looking for running services..."
    Get-Service | Select-Object Name, DisplayName, Status | Format-Table -AutoSize >> "$path\System Information\Running Services.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Running services copied OK" -path $path
    # Installed Programs
    Write-Host "$(Get-Dots) Checking installed programs..."
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Format-Table -AutoSize >> "$path\System Information\Installed Programs.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Installed Programs copied OK" -path $path
    # Schedule Tasks
    Write-Host "$(Get-Dots) Obtaining scheduled tasks..."
    Get-ScheduledTask | Select-Object Actions, Author, TaskName, TaskPath, URI, Triggers >> "$path\System Information\Scheduled Tasks.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Scheduled tasks copied OK" -path $path
    # Active users / Kerberos Sessions
    Write-Host "$(Get-Dots) Obtaining active users / Kerberos sessions..."
    query user /server:$server >> "$path\System Information\Active Users.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Active users copied OK" -path $path
    # Administrator users
    Write-Host "$(Get-Dots) Looking for administrator users..."
    $language = (Get-WinSystemLocale).Name; if ($language -match 'es-') { $adminGroupName = "Administradores" } else { $adminGroupName = "Administrators" }; $adminGroupMembers = Get-LocalGroupMember -Group $adminGroupName | Select-Object Name, ObjectClass; $outputPath = "$path\System Information\Administrator Users.txt"; $adminGroupMembers | Out-File -FilePath $outputPath -Encoding utf8; Add-Log -message "[+] $(Get-CurrentTime) - Administrator users copied OK" -path $path
    # Local users
    Write-Host "$(Get-Dots) Detecting local users..."
    Get-LocalUser | Format-Table >> "$path\System Information\Active Users.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Local users copied OK" -path $path
    # Process CommandLine
    Write-Host "$(Get-Dots) Searching for process command lines..."
    Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine, Path | Format-List >> "$path\System Information\Processes CommandLines.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Processes commandLines copied OK" -path $path
    # Powershell History
    Write-Host "$(Get-Dots) Extracting Powershell history..."
    Get-History >> "$path\System Information\Powershell History.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Powershell history copied OK" -path $path
    # Recently installed software
    Write-Host "$(Get-Dots) Extracting recently installed software..."
    Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Format-List * >> "$path\System Information\Recently Installed Software.txt" ; Add-Log -message "[+] $(Get-CurrentTime) - Recently installed software copied OK" -path $path
}

# Get Application, System and Security
function Get-WindowsLogs {

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




Get-System -path $WorkingFolder
ConvertTo-Zip -folderPath $WorkingFolder