# Fix-Log4j-PowershellScript (CVE-2021-44228)

[![PSScriptAnalyzer](https://github.com/sysadmin0815/Fix-Log4j-PowershellScript/actions/workflows/powershell-analysis.yml/badge.svg)](https://github.com/sysadmin0815/Fix-Log4j-PowershellScript/actions/workflows/powershell-analysis.yml)

<b>search and remove JNDI Lookup Class from *log4j*.jar files on the system with Powershell (Windows) </b> <br>
make sure you use the latest script release! <br>

## Release version 1.6.2 and above
Killmode for Java processes implemented. ($killMode)<br>
<b>defaults to $false</b> if not changed manually! Be careful using this feature!<br>
<br>
<h3>the script can be deployed manually, with GPO or deployment tools like SCCM.</h3>
<br>
<h3> Features and Info:</h3>
<b> by default the script searches on C:\ </b> if not changed<br>
 -can be changed to search on all local drives with $searchAllDrives = $true in the script<br>
 -can be changed to search a specific path with $searchPath = "C:\your\folder\to\search\ <br><br>

<b>by default the script creates a backup</b> of the file(s) in the same folder were the jar files was found, before removing the class<br>
 -can be disabled with $enableBackup set to $false in the script<br>

<b>by default the script validates if the jndilookup.class has been removed</b> from the jar file <br> <br>
<b> by default if the class is still detected</b> and the jar file was not modified, the backup file will be cleaned up.<br>
 -can be disabled with $removeBkOnFailure set to $false<br>
 
<b> by default the script searches for running java processes</b> and write a warning in the log and console.<br>
 -KillMode for java prcesses can be enabled by $killMode set to $true - be careful with that!<br>

<b>Generate a log file</b> in the scripts root directory <br><br>
<b>Generate readable console output</b> <br> <br> 

<h3> How to run the script:</h3>
<b> Please read the script and modify it if needed before you execute it!</b><br>
execute the script with elevated Powershell.exe or with deploment tools like SCCM.<br>
"powershell.exe -file "C:\Path\To\Script\Fix-log4j_jndi_7zip.ps1" -executionpolicy Bypass"
<br>
<br>
Tested on Windows 10, Server 2012R2, 2016 and 2019.<br>

<h3>Credits:</h3>

7-Zip is used to delete the class in the jar file and verify the removal.
>  Source: https://www.7-zip.org/ <br>
>  7-Zip Copyright (C) 1999-2021 Igor Pavlov.

<br>
<br>
<b>THE SCRIPT IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND.</b> <br>
