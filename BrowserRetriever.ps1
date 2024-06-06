#################################################################
#                  DFIR - Tool Box                              #
#   Coded by Alberto Aparicio (alberto.aparicio@masorange.es)   #
#   Version: 1.0                                                #
#   Description: Retrieve different system artifacts            #
#################################################################

param (
    [Alias("h")][switch]$help,
    [Alias("hb")][switch]$harvestBrowsers,
    [Alias("pf")][switch]$prefetch,
    [Alias("a")][switch]$all
)

#################################################################
#                           FUNCTIONS                           #
#################################################################

# Display help message
function Show-Help {
    Write-Host "Usage: Odin.ps1 [-h | --help] [-hb | --harvest-browsers] [-a | --all] [-pf | --prefetch]" 
    Write-Host "`nOptions:" 
    Write-Host "  -h, --help                  Show this help message and exit"
    Write-Host "  -hb, --harvest-browsers     Harvest browser artifacts"
    Write-Host "  -pf, --prefetch             Extract prefetch files"
    Write-Host "  -a, --all                   Extract all defined evidences (future implementation)"
}

# Check if the current user running the script is Administrator
function Check-IfAdmin {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        return $isAdmin
    } catch {
        Write-Error "An error occurred: $_"
        return $false
    }
}

# Copy files if they exist
function Copy-FileIfExist {
    param (
        [string]$source,
        [string]$destination,
        [string]$browserName,
        [string]$folder,
        [string]$artifact
    )

    if (Test-Path $source) {
        if (Test-Path $source -PathType Container) {
            # Ensure destination is a folder
            $destinationFolder = $destination
            if (-not (Test-Path $destinationFolder)) {
                New-Item -Path $destinationFolder -ItemType Directory | Out-Null
            }
            Copy-Item -Path "$source\*" -Destination $destinationFolder -Recurse -Force
        } else {
            Copy-Item -Path $source -Destination $destination -Force
        }
        Write-Output "  [+] $browserName - $artifact copied";
        # Add info to log file
        $CurrentTime = Current-Time
        Add-Log -message "[+] $CurrentTime - $browserName - $artifact copied ok: $destination" -path $folder
    }  else {
        Write-Host "  [-] $browserName - $artifact not found"
        # Add info to log file
        $CurrentTime = Current-Time
        Add-Log -message "[-] $CurrentTime - $browserName - $artifact not found" -path $folder
    }
}

# Compress all evidences into zip file
function Zip-Evidences {
    param (
        [string]$folderPath
    )
    Write-Host "[+] Compressing evidences..."
    # Add info to log file
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Zipping evidences into $folderPath.zip" -path $folderPath

    # Add info to log file
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Compressed evidences OK: $folderPath.zip" -path $folderPath

    Compress-Archive -Force -LiteralPath $folderPath -DestinationPath "$folderPath.zip"
    Write-Host "[+] Evidences compressed in $folderPath.zip"
}

# Delete the directory
function Remove-WorkingFolder {
    param (
        [string]$folderPath
    )
    Remove-Item -Path $folderPath -Recurse -Force
}

# Check if a program is installed by searching registry keys
function Get-InstalledPrograms {
    $programs = @()

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $registryPaths) {
        $programs += Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                     Select-Object DisplayName, DisplayVersion, Publisher
    }
    # Add info to log file
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Obtaining installed programs..." -path $WorkingFolder
    return $programs
}

# Detect Common Browsers
function Detect-Browsers {
    $browsers = @()
    $installedPrograms = Get-InstalledPrograms

    $browserNames = @(
        "Google Chrome",
        "Mozilla Firefox",
        "Microsoft Edge",
        "Opera",
        "Brave"
    )

    Write-Host "[+] Detected installed browsers:"

    foreach ($browser in $browserNames) {
        $browserInstalled = $installedPrograms | Where-Object { 
            $_.DisplayName -match $browser -and 
            $_.DisplayName -notmatch "Update" -and 
            $_.DisplayName -notmatch "Runtime" 
        }
        if ($browserInstalled) {
            $browsers += $browserInstalled | Select-Object -Unique DisplayName, DisplayVersion
            Write-Host "    [x] $browser"
        }
    }

    return $browsers;
}

# Add information to log file
function Add-Log {
    param (
        [string]$message,
        [string]$path
    )
    Add-Content -Path "$path\var.log" -Value $message
}

# Get Current Time
function Current-Time {
    Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
}

#################################################################
#                    RETRIEVE PREFETCH FILES                    #
#################################################################

function Retrieve-Prefetch {
    $CurrentPath = $pwd
    $ExecutionTime = $(get-date -f yyyy-MM-dd)
    $WorkingFolder = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"
    Write-Host "[+] Extracting Prefetch files..."
    # Aquí añade la lógica para extraer los archivos Prefetch
    $prefetchPath = "$env:SystemRoot\Prefetch"
    $destinationPath = "$WorkingFolder\Prefetch"

    if (-not (Test-Path $destinationPath)) {
        New-Item -Path $destinationPath -ItemType Directory | Out-Null
    }

    if (Test-Path $prefetchPath) {
        Copy-Item -Path "$prefetchPath\*" -Destination $destinationPath -Recurse -Force
        Write-Host "[+] Prefetch files copied."
        $CurrentTime = Current-Time
        Add-Log -message "[+] $CurrentTime - Prefetch files copied to: $destinationPath" -path $WorkingFolder
    } else {
        Write-Host "[-] Prefetch directory not found."
        $CurrentTime = Current-Time
        Add-Log -message "[-] $CurrentTime - Prefetch directory not found." -path $WorkingFolder
    }
}

#################################################################
#                    RETRIEVE BROWSER ARTIFACTS                 #
#################################################################

# Define the artifacts for each browser
$chromeArtifacts = @(
    @{ name = "History"; path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" },
    @{ name = "Cookies"; path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies" },
    @{ name = "Cache"; path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache" },
    @{ name = "Extensions"; path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" },
    @{ name = "Login Data"; path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" }
)

$edgeArtifacts = @(
    @{ name = "History"; path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" },
    @{ name = "Cookies"; path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies" },
    @{ name = "Cache"; path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache" },
    @{ name = "Extensions"; path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" },
    @{ name = "Login Data"; path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" }
)

$firefoxProfilePath = (Get-ChildItem -Path "$env:APPDATA\Mozilla\Firefox\Profiles" | Where-Object { $_.PSIsContainer })[0].FullName
$firefoxArtifacts = @(
    @{ name = "History"; path = "$firefoxProfilePath\places.sqlite" },
    @{ name = "Cookies"; path = "$firefoxProfilePath\cookies.sqlite" },
    @{ name = "Cache"; path = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\cache2\entries" },
    @{ name = "Extensions"; path = "$firefoxProfilePath\extensions" },
    @{ name = "Login Data"; path = "$firefoxProfilePath\logins.json" }
)

$operaArtifacts = @(
    @{ name = "History"; path = "$env:APPDATA\Opera Software\Opera Stable\History" },
    @{ name = "Cookies"; path = "$env:APPDATA\Opera Software\Opera Stable\Cookies" },
    @{ name = "Cache"; path = "$env:LOCALAPPDATA\Opera Software\Opera Stable\Cache" },
    @{ name = "Extensions"; path = "$env:APPDATA\Opera Software\Opera Stable\Extensions" },
    @{ name = "Login Data"; path = "$env:APPDATA\Opera Software\Opera Stable\Login Data" }
)

$braveArtifacts = @(
    @{ name = "History"; path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\History" },
    @{ name = "Cookies"; path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cookies" },
    @{ name = "Cache"; path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache" },
    @{ name = "Extensions"; path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Extensions" },
    @{ name = "Login Data"; path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data" }
)

# Function to retrieve artifacts for installed browsers
function Retrieve-BrowserArtifacts {
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Starting to analyze browser artifacts..." -path $WorkingFolder
    $installedBrowsers = Detect-Browsers
    foreach ($browser in $installedBrowsers) {
        if ($browser.DisplayName -match "Google Chrome") {
            # Add detected installed browser to log file
            $CurrentTime = Current-Time
            $browserName = $browser.DisplayName
            Add-Log -message "[+] $CurrentTime - Detected installed browser: $browserName" -path $WorkingFolder
            
            # Create subfolder for Google Chrome
            $chromeFolder = "$WorkingFolder\Google_Chrome"
            mkdir -Force $chromeFolder | Out-Null
            
            # Add info to log file
            $CurrentTime = Current-Time
            Add-Log -message "[+] $CurrentTime - Starting to extract evidences from Google Chrome..." -path $WorkingFolder
            Write-Host "[+] Google Chrome artifacts:"
            
            foreach ($artifact in $chromeArtifacts) {
                $artifactName = $artifact.name
                $artifactPath = $artifact.path
                $destinationPath = "$chromeFolder\Chrome_$artifactName"
                Copy-FileIfExist -source $artifactPath -destination $destinationPath -browserName "Google Chrome" -artifact $artifactName -folder $WorkingFolder
            }
        }
        if ($browser.DisplayName -match "Microsoft Edge") {
            # Add detected installed browser to log file
            $CurrentTime = Current-Time
            $browserName = $browser.DisplayName
            Add-Log -message "[+] $CurrentTime - Detected installed browser: $browserName" -path $WorkingFolder

            # Create subfolder for Microsoft Edge
            $edgeFolder = "$WorkingFolder\Microsoft_Edge"
            mkdir -Force $edgeFolder | Out-Null
            
            # Add info to log file
            $CurrentTime = Current-Time
            Add-Log -message "[+] $CurrentTime - Starting to extract evidences from Microsoft Edge..." -path $WorkingFolder
            Write-Host "[+] Microsoft Edge artifacts:"
            
            foreach ($artifact in $edgeArtifacts) {
                $artifactName = $artifact.name
                $artifactPath = $artifact.path
                $destinationPath = "$edgeFolder\Edge_$artifactName"
                Copy-FileIfExist -source $artifactPath -destination $destinationPath -browserName "Microsoft Edge" -artifact $artifactName -folder $WorkingFolder
            }
        }
        if ($browser.DisplayName -match "Mozilla Firefox") {
            # Add detected installed browser to log file
            $CurrentTime = Current-Time
            $browserName = $browser.DisplayName
            Add-Log -message "[+] $CurrentTime - Detected installed browser: $browserName" -path $WorkingFolder
            
            # Create subfolder for Mozilla Firefox
            $firefoxFolder = "$WorkingFolder\Mozilla_Firefox"
            mkdir -Force $firefoxFolder | Out-Null
            
            # Add info to log file
            $CurrentTime = Current-Time
            Add-Log -message "[+] $CurrentTime - Starting to extract evidences from Mozilla Firefox..." -path $WorkingFolder
            Write-Host "[+] Mozilla Firefox artifacts:"
            
            foreach ($artifact in $firefoxArtifacts) {
                $artifactName = $artifact.name
                $artifactPath = $artifact.path
                $destinationPath = "$firefoxFolder\Firefox_$artifactName"
                Copy-FileIfExist -source $artifactPath -destination $destinationPath -browserName "Mozilla Firefox" -artifact $artifactName -folder $WorkingFolder
            }
        }
        if ($browser.DisplayName -match "Opera") {
            # Add detected installed browser to log file
            $CurrentTime = Current-Time
            $browserName = $browser.DisplayName
            Add-Log -message "[+] $CurrentTime - Detected installed browser: $browserName" -path $WorkingFolder

            # Create subfolder for Opera
            $operaFolder = "$WorkingFolder\Opera"
            mkdir -Force $operaFolder | Out-Null
            
            # Add info to log file
            $CurrentTime = Current-Time
            Add-Log -message "[+] $CurrentTime - Starting to extract evidences from Opera..." -path $WorkingFolder
            Write-Host "[+] Opera artifacts:"
            
            foreach ($artifact in $operaArtifacts) {
                $artifactName = $artifact.name
                $artifactPath = $artifact.path
                $destinationPath = "$operaFolder\Opera_$artifactName"
                Copy-FileIfExist -source $artifactPath -destination $destinationPath -browserName "Opera" -artifact $artifactName -folder $WorkingFolder
            }
        }
        if ($browser.DisplayName -match "Brave") {
            # Add detected installed browser to log file
            $CurrentTime = Current-Time
            $browserName = $browser.DisplayName
            Add-Log -message "[+] $CurrentTime - Detected installed browser: $browserName" -path $WorkingFolder

            # Create subfolder for Brave
            $braveFolder = "$WorkingFolder\Brave"
            mkdir -Force $braveFolder | Out-Null
            
            # Add info to log file
            $CurrentTime = Current-Time
            Add-Log -message "[+] $CurrentTime - Starting to extract evidences from Brave..." -path $WorkingFolder
            Write-Host "[+] Brave artifacts:"
            
            foreach ($artifact in $braveArtifacts) {
                $artifactName = $artifact.name
                $artifactPath = $artifact.path
                $destinationPath = "$braveFolder\Brave_$artifactName"
                Copy-FileIfExist -source $artifactPath -destination $destinationPath -browserName "Brave" -artifact $artifactName -folder $WorkingFolder
            }
        }
    }
}

#################################################################
#                    INFORMATION AND LOG FILE                   #
#################################################################

# Function to create log and information files
function Setup-Environment {
    # Creates Log file
    Write-Host "[+] Creating log file..."

    # Creates working directory
    Write-Host "[+] Creating output directory..."
    $CurrentPath = $pwd
    $ExecutionTime = $(get-date -f yyyy-MM-dd)
    $WorkingFolder = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"
    mkdir -Force $WorkingFolder | Out-Null 
    Write-Host "[+] Output directory created: $WorkingFolder"
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Output directory created ok: $WorkingFolder" -path $WorkingFolder

    # Creates Information file
    ## Hostname
    Write-Host "[+] Creating information file..."
    $HostName = Invoke-Expression -Command 'hostname'
    echo "Hostname: $HostName" > "$WorkingFolder\Information.txt"
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Information file created ok: $WorkingFolder\Information.txt" -path $WorkingFolder

    ## Current user
    $currentUsername = $env:username
    echo "Current Username: $currentUsername" >> "$WorkingFolder\Information.txt"
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Detected current user: $currentUsername" -path $WorkingFolder

    ## Obtain current SID
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userSID = $currentUser.User
    echo "SID: $userSID" >> "$WorkingFolder\Information.txt"
    $CurrentTime = Current-Time
    Add-Log -message "[+] $CurrentTime - Detected current User ID: $userSID" -path $WorkingFolder

    # Current User - ¿is Admin?
    $getPriv = Check-IfAdmin
    if ($getPriv -eq $true) {
        echo "Administrator: YES" >> "$WorkingFolder\Information.txt"
        Write-Host "[+] Is Admin"
    } else {
        echo "Administrator: NO" >> "$WorkingFolder\Information.txt"
        Write-Host "[+] No Admin"
    }

    ## Adquisition Time
    $AdquisitionTime = Get-Date -Format "yyyy-MM-dd HH:mm K"
    echo "Aquisition Time: $AdquisitionTime" >> "$WorkingFolder\Information.txt"
}

#################################################################
#                          MAIN LOGIC                           #
#################################################################

$CurrentPath = $pwd
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$WorkingFolder = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"

if ($help) {
    Show-Help
    exit
}

if (-not ($harvestBrowsers -or $all -or $prefetch)) {
    Show-Help
    exit
}

# Solo configurar el entorno si se selecciona una bandera de extracción
Setup-Environment

if ($harvestBrowsers) {
    Retrieve-BrowserArtifacts
    Zip-Evidences -folderPath $WorkingFolder
    Remove-WorkingFolder -folderPath $WorkingFolder
    exit
}

if ($prefetch) {
    Retrieve-Prefetch
    Zip-Evidences -folderPath $WorkingFolder
    Remove-WorkingFolder -folderPath $WorkingFolder
    exit
}

if ($all) {
    Retrieve-BrowserArtifacts
    Retrieve-Prefetch
    Zip-Evidences -folderPath $WorkingFolder
    Remove-WorkingFolder -folderPath $WorkingFolder
    exit
}

Show-Help
