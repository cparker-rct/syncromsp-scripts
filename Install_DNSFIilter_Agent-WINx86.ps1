###
# Name:         Install_DNS_Filter_Agent-WINx86
# Author:       Chris Parker
# Last Revised: 05/07/2021
# Notes:
# This script is meant to be a base for other installers, mainly .msi files.
# * It detects whether the application is installed by checking for the presence of the main executable in C:\Program Files\ - I wanted to use Get-WmiObject but searching based off of a variable wasn't working
# * If it's not installed, it will grab the installer from the web.
# * For DNS Filter specifically there is a certificate file that must be added to the OS and Firefox told to use the OS Certificate store.
# * There are future plans to uninstall & reinstall if the application is already installed. I'm thinking via wrapping the install/uninstall into functions. Install function should check again if it's installed, and abort if we tried uninstalling it in the first place.
###

Import-Module $env:SyncroModule

# MSP specific variables
$mspName = "RCT"
$scriptLogName = "[$($mspName)-Script]"
$workingDir = "C:\$($mspName)\tmp\$($appName)"

# Application specific variables
$appName = "DNSFilter Agent"
$installedAppPath = "C:\Program Files\DNSFilter Agent\DNSFilter Agent.exe"
$installerURL = "https://download.dnsfilter.com/User_Agent/Windows/DNS_Agent_Setup.msi"
$installerPath = "$($workingDir)\DNS_Agent_Setup.msi"

# Supporting files & other odds and ends
$urlCRT = "https://app.dnsfilter.com/certs/NetAlerts.cer"
$fileCRTPath = "$($workingDir)\NetAlerts.cer"
$ffpath = "HKLM:\Software\Policies\Mozilla\lockPref"
$ffname = "security.enterprise_roots.enabled"
$ffvalue = "1"

Write-Output "$scriptLogName Checking if $appName is already installed."
if (!(Test-Path $installedAppPath)) {
    Write-Output "$scriptLogName $appName doesn't appear to be installed, continuing with install."

    Write-Output "$scriptLogName Checking if $workingDir directory exists."
    if (!(Test-Path $workingDir)) {
        Write-Output "$scriptLogName Creating $workingDir as it doesn't exist yet."
        New-Item -ItemType Directory -Force -Path $workingDir
    }

    Write-Output "$scriptLogName Checking if $appName Site Key is stored in customer record."
    if ($dnsKey -ne "") {
        Write-Output "$scriptLogName Downloading $appName."
        Invoke-WebRequest -Uri $installerURL -OutFile $installerPath
            
        if (!(Test-Path $installerPath)) {
            Write-Output "$scriptLogName $appName failed to download - ABORTING"
            exit 1
        }

        else {
            Write-Output "$scriptLogName Installing $appName."
            msiexec /qn /i "$installerPath" NKEY="$dnsKey" TRAYICON="disabled"

            Write-Output "$scriptLogName Checking if $appName is installed."

            #$installedApps = Get-WmiObject -Class Win32_Product | Select-Object Name
            # couldn't make this work to use $appName - using Test-Path instead
            #if ($installedApps -like '*dnsfilter agent*') {

            if (Test-Path $installedAppPath) {
                Write-Output "$scriptLogName $appName appears to be installed."
                Write-Output "$scriptLogName Downloading DNSFilter Certificate."
                Invoke-WebRequest -Uri $urlCRT -OutFile $fileCRTPath
                
                if (!(Test-Path $fileCRTPath)) {
                    Write-Output "$scriptLogName DNSFilter Certificate failed to download - ABORTING"
                    exit 1
                }
                    
                else {
                    Write-Output "$scriptLogName Installing DNSFilter Certificate."
                    certutil -addstore -enterprise -f "Root" $fileCRTPath
                    Write-Output "$scriptLogName Telling Firefox to use the Windows certificate store."
                    New-Item -Path $ffpath -Force
                    New-ItemProperty -Path $ffpath -Name $ffname -Value $ffvalue -PropertyType DWORD -Force | Out-Null
                    Write-Output "$scriptLogName Cleaning up temporary files."
                    Remove-Item -Recurse -Force $workingDir
                }
            }
                
            else {
                Write-Output "$scriptLogName $appName doesn't appear to be installed - FAILURE"
                exit 1
            }
        }
    }

    else {
        Write-Output "No DNSFilter Site Key Detected - ABORTING"
        exit 1
    }
}

else {
    Write-Output "$scriptLogName $appName is already installed - ABORTING"
    exit 1
}