# Fix-Log4j_JNDI_7zip.ps1
# search and remove JNDI class from *log4j*.jar files on the system ( C:\ - drive by default) - can be changed with $log4jFiles
#
# Author: sysadmin0815
# Date: 16.12.2021
#############################
# Mod. Date: 17.12.2021
# Version 1.4
#Change Log:
#   added additional if check to stop the process of bk file not found.
#   added PSScriptRoot for 7zip by default
#   added $enableBackup
#   added $searchAllDrives
#############################
#THE SCRIPT IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND.
#7zip is used to remove the jndi class Source: https://www.7-zip.org/
#############################
#log4j JNDI class cleanup script
#needs 7zip and admin rights
#powershell 3.0+
#Tested on Win10 and Server 2012R2, 2016 and 2019

#run the script in elevated powershell.exe
#powershell.exe -file "C:\Path\To\Script\Fix-log4j_jndi_7zip.ps1" -executionpolicy Bypass


# 7Zip
#For executing with already installed 7zip or for testing purpose us this below
#$7zipPath = "C:\ProgramFiles\7-Zip\7z.exe"
#For default execution or SCCM deployment use this below. Requires the 7-Zip folder in directory of the script.
$7zipPath = $PSScriptRoot+"\7-Zip\7za.exe"

#set to $true to search all drives on the system for pattern; $searchpath will be ignored.
#if set to $false the script will search in $searchpath only for pattern
$searchAllDrives = $false

#define pattern and search path; default $searchPath = "C:\" 
$searchPath = "C:\"                     # will be ignored if $searchAllDrives is $true
$filePattern = "*log4j*.jar"

#Enable jar file backup in the same directory before removing class?
#set to $true to enable backup (recommended)
#set to $false to disable backup
$enableBackup =  $true


# -------------- SCRIPT START ---------------


#Test for Admin permissons, if not admin exit script.
if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script with Admin permissions!"
    exit 1
}

#Get date and time for log
$date = (Get-Date -Format "ddMMyyyy_HHmm")
$datelog = (Get-Date -Format "dd.MM.yyyy HH:mm:ss")

#check for existing Log folder
$rootFolder = $PSScriptRoot+"\"
$logFileName="Log4JCleanup.log"
$folderName = "Log"
$PathLogs= $rootFolder
$Path= $rootFolder+$folderName
$PathToLogFile = $Path+"\"+$logFileName

#Test for Log Folder if not create it
if (!(Test-Path $Path)) {
    New-Item -itemType Directory -Path $PathLogs -Name $folderName -ErrorAction SilentlyContinue
}
else {
    Write-Host "[INFO] LogFolder already exists." -ForegroundColor Green
}

#Test for Log File if not create it
if (!(Test-Path $PathToLogFile)) {
    New-Item -itemType File -Path $Path -Name $logFileName -ErrorAction SilentlyContinue
    Add-Content -Path $PathToLogFile -Value "$datelog     *** ***    NEW LOG   *** ***   "
}
else {
    Write-Host "[INFO] LogFile already exists." -ForegroundColor Green
    Add-Content -Path $PathToLogFile -Value ""
    Add-Content -Path $PathToLogFile -Value "$datelog     *** ***    NEW LOG   *** ***   "
}

#Test for 7Zip folder
if ( ! (Test-Path -Path $7zipPath) ) {
    Write-Warning "Can not find 7zip in $7zipPath"
    Write-Warning "Please verify the folder and 7zip.exe exist."
    exit 1
}

if ($searchAllDrives) {
    Write-Host "Searching on all drives. This can take a while..." -ForegroundColor Yellow
    Add-Content -Path $PathToLogFile -Value "$datelog   -- Start search on all drives"
    $log4jFiles = Get-PSDrive -PSProvider FileSystem | ForEach-Object {(Get-ChildItem ($_.Root) -Recurse -Force -Include $filepattern -ErrorAction SilentlyContinue)} |  Where-Object {($_.PSIsContainer -eq $false)} 
}
else {
    Write-Host "Searching in $searchPath . This can take a while..." -ForegroundColor Yellow
    Add-Content -Path $PathToLogFile -Value "$datelog   -- Start search in $searchPath"
    $log4jFiles = get-childitem -Path $searchPath -include $filePattern -File -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.PSIsContainer -eq $false)} 
}

if  (! $log4jFiles -or $log4jFiles.Length -eq 0){
    Write-Host "No files found matching pattern $filepattern in Path $searchPath" -BackgroundColor Green
    Add-Content -Path $PathToLogFile -Value "$datelog   -- No files found matching pattern $filepattern in Path $searchPath"
    $returnCode = 0
}
else {
    $returnCode = 0

    Write-Host "The folloging files where found:" -ForegroundColor Yellow
    Write-Output  $log4jFiles.FullName
    Add-Content -Path $PathToLogFile -Value "$datelog   -- Files found matching pattern $filepattern in Path $searchPath"
    $log4jFiles.FullName | Add-Content $PathToLogFile

    foreach ($file in $log4jFiles) {
        try{ 
            if ($enableBackup) {
                $filebkpath = $file.FullName+"_"+$date+".bk"
                Copy-Item $file.fullname -Destination $filebkpath -Force
                if (! $filebkpath) {
                    Write-Host "Error creating backup for file $file" -BackgroundColor Red -ForegroundColor Yellow
                    Add-Content -Path $PathToLogFile -Value "$datelog   -- Error creating backup for file $file"
                    $returnCode = 1
                }
                else{
                    Add-Content -Path $PathToLogFile -Value "$datelog   -- Backup file to $filebkpath"
                    Add-Content -Path $PathToLogFile -Value "$datelog   -- Processing file $file"
                    & $7zipPath d $file.fullname org/apache/logging/log4j/core/lookup/JndiLookup.class
                }
            }

            else{   
                Add-Content -Path $PathToLogFile -Value "$datelog   -- Backup disabled for file $file"
                Add-Content -Path $PathToLogFile -Value "$datelog   -- Processing file $file"
                & $7zipPath d $file.fullname org/apache/logging/log4j/core/lookup/JndiLookup.class
                }

        }
        catch{
            Write-Host "[ERROR] Can not execute JNDI cleanup for file $file " -BackgroundColor Red -ForegroundColor Yellow
            Write-Warning $Error[0]
            $Error[0] | Add-Content $PathToLogFile
            $returnCode = 1
        }
    }
}

#comment this line below to not automatically close the script.
exit $returnCode
