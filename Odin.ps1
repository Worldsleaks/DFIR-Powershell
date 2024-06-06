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
        [string]$tab,
        [string]$file
    )
    if ($tab -eq "yes") {
        # Activated tab
        if ($result -eq $false) {
            Write-Host "    - [FAIL]" -ForegroundColor Red -NoNewline
            Remove-Item -Path $file -Force 
            Add-Log -message " [FAIL] $(Get-CurrentTime) - $artifact couldn't be copied!!" -path $path
        } else {
            Write-Host "    - [ OK ]" -ForegroundColor Green -NoNewline
            Add-Log -message "[ OK ] $(Get-CurrentTime) - $artifact copied" -path $path
        }
    } else {
        # Non activated tab
        if ($result -eq $false) {
            Write-Host "[FAIL]" -ForegroundColor Red -NoNewline
            Remove-Item -Path $file -Force 
            Add-Log -message "[FAIL] $(Get-CurrentTime) - $artifact couldn't be copied!!" -path $path
        } else {
            Write-Host "[ OK ]" -ForegroundColor Green -NoNewline
            Add-Log -message "[ OK ] $(Get-CurrentTime) - $artifact copied" -path $path
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
        Write-Host "    - [ OK ]" -ForegroundColor Green -NoNewline
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
    Get-ComputerInfo >> "$path\System Information\ComputerInfo.txt" ; Invoke-CheckExecution -result $? -artifact "Computer information" -tab yes -file "$path\System Information\ComputerInfo.txt"
    Write-Host " Computer Information"
    
    # NetIPConfiguration
    Get-NetIPConfiguration >> "$path\System Information\NetIPConfiguration.txt" ; Invoke-CheckExecution -result $? -artifact "Network configuration" -tab yes -file "$path\System Information\NetIPConfiguration.txt"
    Write-Host " Network Configuration"

    # Active connections
    Get-NetTCPConnection >> "$path\System Information\Active Connections.txt" ; Invoke-CheckExecution -result $? -artifact "Active connections" -tab yes -file "$path\System Information\Active Connections.txt"
    Write-Host " Active network connections"  
    
    # Firewall Rules
    Get-NetFirewallRule -ErrorAction SilentlyContinue >> "$path\System Information\Firewall Rules.txt" ; Invoke-CheckExecution -result $? -artifact "Firewall rules" -tab yes -file "$path\System Information\Firewall Rules.txt"
    Write-Host " Firewall rules"  
    
    # IP Address
    Get-NetIPAddress >> "$path\System Information\IPAddresses.txt" ; Invoke-CheckExecution -result $? -artifact "Firewall rules" -tab yes -file "$path\System Information\IPAddresses.txt"
    Write-Host " Network Information"  
    
    # DNS Cache
    Get-DnsClientCache | Format-List >> "$path\System Information\DNS Cache.txt" ; Invoke-CheckExecution -result $? -artifact "DNS cache" -tab yes -file "$path\System Information\DNS Cache.txt"
    Write-Host " DNS cache" 

    # Running processes  
    Get-Process >> "$path\System Information\Running Processes.txt" ; Invoke-CheckExecution -result $? -artifact "Running processes" -tab yes -file "$path\System Information\Running Processes.txt"
    Write-Host " Running processes" 
    
    # Running Services
    Get-Service | Select-Object Name, DisplayName, Status | Format-Table -AutoSize >> "$path\System Information\Running Services.txt" ; Invoke-CheckExecution -result $? -artifact "Running services" -tab yes -file "$path\System Information\Running Services.txt"
    Write-Host " Running services"  

    # Process CommandLine
    Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine, Path | Format-List >> "$path\System Information\Processes CommandLines.txt" ; Invoke-CheckExecution -result $? -artifact "Processes commandlines" -tab yes -file "$path\System Information\Processes CommandLines.txt"
    Write-Host " Process command lines"  

    # Network Shares
    Get-ChildItem -file HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\ >> "$path\System Information\Network Shares.txt" ; Invoke-CheckExecution -result $? -artifact "Network shares" -tab yes -file "$path\System Information\Network Shares.txt"
    Write-Host " Network shares"  

    # SMB Shares
    Get-SmbShare >> "$path\System Information\SMB Shares.txt" ; Invoke-CheckExecution -result $? -artifact "SMB shares" -tab yes -file "$path\System Information\SMB Shares.txt"
    Write-Host " SMB shares"   

    # Recently installed software
    Get-WinEvent -ProviderName msiinstaller | Where-Object id -eq 1033 | Select-Object timecreated,message | Format-List * >> "$path\System Information\Recently Installed Software.txt" ; Invoke-CheckExecution -result $? -artifact "Recently installed software" -tab yes -file "$path\System Information\Recently Installed Software.txt"
    Write-Host " Recently installed software" 

    # Installed Programs
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Format-Table -AutoSize >> "$path\System Information\Installed Programs.txt" ; Invoke-CheckExecution -result $? -artifact "Installed programs" -tab yes -file "$path\System Information\Installed Programs.txt"
    Write-Host " Installed programs"   

    # Schedule Tasks
    Get-ScheduledTask | Select-Object Actions, Author, TaskName, TaskPath, URI, Triggers >> "$path\System Information\Scheduled Tasks.txt" ; Invoke-CheckExecution -result $? -artifact "Scheduled tasks" -tab yes -file "$path\System Information\Scheduled Tasks.txt"
    Write-Host " Scheduled tasks"  

    # Local users
    Get-LocalUser | Format-Table >> "$path\System Information\Local Users.txt" ; Invoke-CheckExecution -result $? -artifact "Active users" -tab yes -file "$path\System Information\Local Users.txt"
    Write-Host " Local users"  

    # Administrator users
    $language = (Get-WinSystemLocale).Name; $adminGroupName = if ($language -match 'es-') { "Administradores" } else { "Administrators" }; $adminGroupMembers = Get-LocalGroupMember -Group $adminGroupName | Select-Object Name, ObjectClass; $outputPath = "$path\System Information\Administrator_Users.txt"; $adminGroupMembers | Out-File -FilePath $outputPath ; Invoke-CheckExecution -result $? -artifact "Administrator users" -tab yes -file "$path\System Information\Administrator_Users.txt"
    Write-Host " Administrator users" 

    # RDP Sessions
    qwinsta /server:localhost >> "$path\System Information\Open Sessions.txt" ; Invoke-CheckExecution -result $? -artifact "Open sessions" -tab yes -file "$path\System Information\Open Sessions.txt"
    Write-Host " Open Sessions"  
}

# Get Event Viewer Log
function Get-EventViewerFiles {
    param (
        [string]$path
    )
    Write-Host "$(Invoke-InfoDot) Collecting important Event Viewer Files..."
    New-Item -Path $path -Name "Event Viewer" -ItemType Directory -Force | Out-Null
    $EventViewer = "$path\Event Viewer"
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" | Where-Object {$_.BaseName -in $channels} | ForEach-Object {
        $artifactName = $_.Name
        $sourcePath = $_.FullName
        $destinationPath = "$EventViewer\$artifactName"
        Copy-Item -Path $sourcePath -Destination $destinationPath
        Invoke-CheckExecution -result $? -artifact $artifactName -tab yes -file "$path\Event Viewer\$($artifactName).evtx"
        Write-Host " $($artifactName)"
    }
} 

# Powershell history from all users
function Get-AllPowershellHistory {
    param (
        [string]$path
    )
    Write-Host "$(Invoke-InfoDot) Collecting all powershell histories from all users..."
    $PowershellConsoleHistory = "$path\All PowerShell History"
    # Specify the directory where user profiles are stored
    $usersDirectory = "C:\Users"
    # Get a list of all user directories in C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    Add-Log -message "[INFO] $(Get-CurrentTime) - Started to extract all users powershell history..." -path "$folderPath"
    foreach ($userDir in $userDirectories) {
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = "$PowershellConsoleHistory\$userDir.Name" ; Invoke-CheckExecution -result $? -artifact "$($userDir.FullName) powershell history" -tab yes -path $path
            Write-Host " Powershell history from '$($userDir.Name)'"
            mkdir -Force $outputDirectory | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
            }
        }
}  

# Get all files from all the users outlook cache
function Get-OutlookCache {
    param (
        [string]$path
    )
    # Define el directorio raíz para guardar las caches de Outlook
    $rootDestPath = "$path\Outlook Cache"

    # Comienza el proceso de extracción
    Write-Output "[INFO] Starting to extract Outlook Cache..."

    # Obtiene los perfiles de usuario en el sistema
    $userProfiles = Get-ChildItem -Path "C:\Users" | Where-Object { $_.PSIsContainer -and $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($profile in $userProfiles) {
        # Define la ruta de la cache de Outlook para cada usuario
        $cachePath = "C:\Users\$($profile.Name)\AppData\Local\Microsoft\Windows\INetCache\Content.MSO"
        
        # Verifica si la ruta de la cache existe
        if (Test-Path -Path $cachePath) {
            # Define el directorio de destino para la copia de la cache
            $destPath = "$rootDestPath\$($profile.Name)"
            
            # Intenta crear el directorio de destino y copiar la cache
            try {
                New-Item -ItemType Directory -Force -Path $destPath | Out-Null
                Copy-Item -Path "$cachePath\*" -Destination $destPath -Recurse -Force
                Write-Host "    - [ OK ]" -NoNewline -ForegroundColor Green
                Write-Host " $($profile.Name)"
            } catch {
                Write-Host "    - [FAIL]" -NoNewline -ForegroundColor Red
                Write-Host " $($profile.Name)"
            }
        } else {
            Write-Host "    - [FAIL]" -NoNewline -ForegroundColor Red
            Write-Host " $($profile.Name)"
        }
    }
}

# Get a listing of the temp files from each user in the system
function Get-TempFiles {

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
    Get-OutlookCache -path $WorkingFolder
}

function Invoke-WithAdminPrivilege {
    Get-EventViewerFiles -path $WorkingFolder
    Get-AllPowershellHistory -path $WorkingFolder
}

Invoke-WithoutAdminPrivilege
if ($isAdmin) {
    Invoke-WithAdminPrivilege
}

ConvertTo-Zip -folderPath $WorkingFolder
