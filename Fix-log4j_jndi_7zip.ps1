# Fix-Log4j_JNDI_7zip.ps1
# search and remove JNDI class from *log4j*.jar files on the system ( C:\ - drive by default)
# search scope can be changed to search on all local drives with $searchAllDrives set to $true
#
# Author: sysadmin0815
# Date: 16.12.2021
#############################
# Mod. Date: 23.12.2021
$scriptVersion = "1.6.2"
#Change Log:
#   added additional if check to stop the process of bk file not found.
#   added PSScriptRoot for 7zip by default
#   added $enableBackup
#   added $searchAllDrives
#   added verifying process if jndilookup class was removed from jar file
#   bugfix and code cleanup
#   added killMode for java processes
#
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

#define pattern and search path; default $searchPath = "C:\" ; Always use \ at the end of the path!!
$searchPath = "C:\"                     # will be ignored if $searchAllDrives is $true
$filePattern = "*log4j*.jar"

#Enable jar file backup in the same directory before removing class?
#--- set to $true to enable backup (recommended)
#--- set to $false to disable backup
$enableBackup =  $true

#Explaination:
#Each jar file which matches the pattern will be backed up in the same directory as *.bk file before the script
#removes the class from the jar file. 
#Then the script searches for the jndilookup class in the jar file to verify it was removed.
#If the class is still detected after the script ran, the original jar file was not modified.
#
#If the validation of jndilookup class removal fails, delete the created backup files to keep the system clean.
#if the class was NOT removed successfully, the jar file was NOT modified. So keeping the bk file is optional.
#--- set to $true to delete bk files if the class is still detected in the jar file (default)
#--- set to $false to keep bk files if the class is still detected in the jar file.
#will be ignored if $enableBackup is set to $false
$removeBkOnFailure = $true                  #set to $false if you are not sure

#Enable KillMode
# ATTENTION!
#if killmode is set to $true the scrip will terminate all processes matching the pattern $processName
#the process(es) wont be started automatically again!
#be careful using this option!
#set to $true to enable killmode
$killMode = $false                         #default value set to $false
$processName = 'java'

# -------------- SCRIPT START ---------------


#Test for Admin permissons, if not admin exit script.
if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script with Admin permissions!"
    exit 1
}

#Get date and time for log
$date = (Get-Date -Format "ddMMyyyy_HHmm")
$datelog = (Get-Date -Format "dd.MM.yyyy HH:mm:ss")

#Buid LogFolder and LogFile
$rootFolder = $PSScriptRoot+"\"
#$rootFolder = "C:\Windows\Logs\Custom\"            #if you want the logs stored in a different folder, modify this line and comment the above one.
$logFileName="Log4JCleanup.log"
$folderName = "Log"
$PathLogs= $rootFolder
$Path= $rootFolder+$folderName
$PathToLogFile = $Path+"\"+$logFileName

#Test for Log Folder if not create it
if (!(Test-Path $Path)) {
    Write-Host "[INFO] Creating LogFolder $Path" -ForegroundColor Yellow
    New-Item -itemType Directory -Path $PathLogs -Name $folderName -ErrorAction SilentlyContinue | Out-Null
}
else {
    Write-Host "[INFO] LogFolder already exists." -ForegroundColor Green
}

#Test for Log File if not create it
if (!(Test-Path $PathToLogFile)) {
    Write-Host "[INFO] Creating LogFile $PathToLogFile" -ForegroundColor Yellow
    New-Item -itemType File -Path $Path -Name $logFileName -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $PathToLogFile -Value "$datelog     *** ***    NEW LOG   *** ***   "
    Add-Content -Path $PathToLogFile -Value "$datelog     Computer Name: $env:computername   "
    Add-Content -Path $PathToLogFile -Value "$datelog     Script Version: $scriptVersion   "
}
else {
    Write-Host "[INFO] LogFile already exists." -ForegroundColor Green
    Add-Content -Path $PathToLogFile -Value ""
    Add-Content -Path $PathToLogFile -Value "$datelog     *** ***    NEW LOG   *** ***   "
    Add-Content -Path $PathToLogFile -Value "$datelog     Computer Name: $env:computername   "
    Add-Content -Path $PathToLogFile -Value "$datelog     Script Version: $scriptVersion   "
}

#Test for 7Zip folder
if ( ! (Test-Path -Path $7zipPath) ) {
    Write-Warning "Can not find 7zip in $7zipPath"
    Write-Warning "Please verify the folder and 7zip.exe exist."
    exit 1
}

#Output of script version
Write-Host "[INFO] Script Version: $($scriptVersion)" -ForegroundColor Yellow

#If $searchAllDrives is true
if ($searchAllDrives) {
    Write-Host ""
    Write-Host "Searching on all drives. This can take a while..." -ForegroundColor Yellow
    Add-Content -Path $PathToLogFile -Value "$datelog   -- Start search on all drives"
    $log4jFiles = Get-PSDrive -PSProvider FileSystem | ForEach-Object {(Get-ChildItem ($_.Root) -Recurse -Force -Include $filepattern -ErrorAction SilentlyContinue)} |  Where-Object {($_.PSIsContainer -eq $false)} 
}
#If $searchAllDrives is false search at $searchPath
else {
    Write-Host ""
    Write-Host "Searching in $searchPath . This can take a while..." -ForegroundColor Yellow
    Add-Content -Path $PathToLogFile -Value "$datelog   -- Start search in $searchPath"
    $log4jFiles = get-childitem -Path $searchPath -include $filePattern -File -Force -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.PSIsContainer -eq $false)} 
}

#If no files with pattern found
if  (! $log4jFiles -or $log4jFiles.Length -eq 0){
    Write-Host "No files found matching pattern $filepattern" -ForegroundColor Green
    Add-Content -Path $PathToLogFile -Value "$datelog   -- No files found matching pattern $filepattern"
    $returnCode = 0
}
#If files with pattern found run this part
else {
    $returnCode = 0

    Write-Host "The following files where found:" -ForegroundColor Yellow
    Write-Output  $log4jFiles.FullName
    Write-Host ""
    Add-Content -Path $PathToLogFile -Value "$datelog   -- Files found matching pattern $filepattern "
    $log4jFiles.FullName | Add-Content $PathToLogFile

        #search for java processes
        Write-Host "Searching for running process(es) matching $processName ..." -ForegroundColor Yellow
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "Running process(es) matching $processName found!" -ForegroundColor Red
            Add-Content -Path $PathToLogFile -Value "$datelog   -- Running process(es) matching $processName found! "
            
            #killmode if enabled
            if ($killMode) {
                Write-Host "[!!] KillMode enabled! The stopped process(es) will not start automatically!" -ForegroundColor Red
                Add-Content -Path $PathToLogFile -Value "$datelog   -- KillMode enabled! "
                foreach ($proc in $process) {
                    Stop-Process $proc -Force -ErrorAction SilentlyContinue
                }
                Write-Host "   -- Process(es) stopped." -ForegroundColor Green
                Add-Content -Path $PathToLogFile -Value "$datelog   -- Process(es) stopped! "
    
            } 
        }
        else {
            Write-Host "No running process(es) matching $processName found!" -ForegroundColor Green
            Add-Content -Path $PathToLogFile -Value "$datelog   -- No process(es) matching $processName found. "
        }

    Write-Host ""
    Write-Host "Start removal of JNDI Lookup Class" -ForegroundColor Yellow

    #define temp file path for validating if jndilookup class was removed (will be deleted automatically)
    $tmpFile = "$PSScriptRoot\log4jcleanupTmp.log"

    #process files found matching pattern
    foreach ($file in $log4jFiles) {
        try{ 
            #if enableBackup is set to $true process this part
            if ($enableBackup) {
                if (Test-Path -Path $tmpFile) {
                    Remove-Item -Path $tmpFile -Force
                }

                #Create backup of jar file
                $filebkpath = $file.FullName+"_"+$date+".bk"
                Copy-Item $file.fullname -Destination $filebkpath -Force
                
                #Verify backup of jar file exists of not abort and output error
                if (Test-Path -Path $filebkpath) {
                    Write-Host "Processing file $file"
                    Write-Host "   -- Created backup file $filebkPath"
                    Add-Content -Path $PathToLogFile -Value "$datelog   Backup file to $filebkpath"
                    Add-Content -Path $PathToLogFile -Value "$datelog   Processing file $file"
                    & $7zipPath d $file.fullname org/apache/logging/log4j/core/lookup/JndiLookup.class | Out-Null
                    Write-Host "   -- Checking if JNDILookup Class has been removed"
                    Start-Process -FilePath $7zipPath -ArgumentList "l `"$($file.FullName)`" org/apache/logging/log4j/core/lookup/JndiLookup.class" -NoNewWindow -Wait -RedirectStandardOutput "$tmpFile"
                    Add-Content -Path $PathToLogFile -Value "$datelog   --- Checking if JNDILookup Class has been removed"
                    #check if jndilookup class was removed
                    $validate = Select-String -Path "$tmpFile" -Pattern "JndiLookup.class" -CaseSensitive -Quiet -SimpleMatch
                    if (! $validate) {
                        Write-Host "   -- Verified: File successully cleaned up." -ForegroundColor Green
                        Add-Content -Path $PathToLogFile -Value "$datelog   --- Verified: File successully cleaned up."
                    } 
                    else {
                        Write-Host "   -- Failure: Check whether you have write permissions or another process is currently using the file." -BackgroundColor Red -ForegroundColor Yellow
                        Add-Content -Path $PathToLogFile -Value "$datelog   --- Failure: Check whether you have write permissions or another process is currently using the file."
        
                        if ($removeBkOnFailure) {
                            Write-Host "   -- Rollback: Removing backup file $filebkpath" -ForegroundColor Yellow
                            Add-Content -Path $PathToLogFile -Value "$datelog   --- Rollback: Removing backup file $filebkpath"
                            Remove-Item $filebkpath
                        }
                        $returnCode = 1
                    }

                    if (Test-Path -Path $tmpFile) {
                        Remove-Item -Path $tmpFile -Force
                    }
                }
                #Error handling if backup file could not be ceated
                else{
                    Write-Host "Error creating backup for file $file" -BackgroundColor Red -ForegroundColor Yellow
                    Write-Host "   -- No changes perfmormed" -BackgroundColor Red -ForegroundColor Yellow
                    Write-Host ""
                    Add-Content -Path $PathToLogFile -Value "$datelog   -- Error creating backup for file $file"
                    Add-Content -Path $PathToLogFile -Value "$datelog      -- No changes performed."
                    $returnCode = 1
                }
            }

            #if enableBackup is set to $false, process this part
            else{
                if (Test-Path -Path $tmpFile) {
                    Remove-Item -Path $tmpFile -Force
                }
                Write-Host "Processing file $file"
                Write-Host "   -- Backup DISABLED" -ForegroundColor Yellow
                Add-Content -Path $PathToLogFile -Value "$datelog   Backup disabled for file $file"
                Add-Content -Path $PathToLogFile -Value "$datelog   Processing file $file"
                & $7zipPath d $file.fullname org/apache/logging/log4j/core/lookup/JndiLookup.class | Out-Null
                Write-Host "   -- Checking if JNDILookup Class has been removed"
                Start-Process -FilePath "$7zipPath" -ArgumentList "l `"$($file.FullName)`" org/apache/logging/log4j/core/lookup/JndiLookup.class" -NoNewWindow -Wait -RedirectStandardOutput "$tmpFile"
                Add-Content -Path $PathToLogFile -Value "$datelog   --- Checking if JNDILookup Class has been removed"
                $validate = Select-String -Path "$tmpFile" -Pattern "JndiLookup.class" -CaseSensitive -Quiet -SimpleMatch
                #check if jndilookup class was removed
                if (! $validate) {
                    Write-Host "   -- Verified: File successully cleaned up." -ForegroundColor Green
                    Add-Content -Path $PathToLogFile -Value "$datelog   --- Verified: File successully cleaned up."
                } 
                else {
                    Write-Host "   -- Failure: Check whether you have write permissions or another process is currently using the file." -BackgroundColor Red -ForegroundColor Yellow
                    Add-Content -Path $PathToLogFile -Value "$datelog   --- Failure: Check whether you have write permissions or another process is currently using the file."
                    $returnCode = 1
                }
                if (Test-Path -Path $tmpFile) {
                    Remove-Item -Path $tmpFile -Force
                }
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

Write-Host ""
Write-Host "The log file is available here: $PathToLogFile" -ForegroundColor Yellow

#comment this line below to not automatically close the script.
exit $returnCode
