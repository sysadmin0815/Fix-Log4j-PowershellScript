# Fix-Log4j-PowershellScript (CVE-2021-44228)

[![PSScriptAnalyzer](https://github.com/sysadmin0815/Fix-Log4j-PowershellScript/actions/workflows/powershell-analysis.yml/badge.svg)](https://github.com/sysadmin0815/Fix-Log4j-PowershellScript/actions/workflows/powershell-analysis.yml)


search and remove JNDI class from *log4j*.jar files on the system with Powershell (Windows) - defaults to C:\ <br>

<b>by default the script creates a backup</b> of the file(s) in the same folder were the jar files was found, before removing the class (can be disabled with $enableBackup in the script)

7-Zip is used to delete the class in the jar file.<br>
>  Source: https://www.7-zip.org/ <br>
>  7-Zip Copyright (C) 1999-2021 Igor Pavlov.

<b> Please read the script and modify it if needed before you execute it!</b>

execute the script with elevated Powershell.exe or with deploment tools like SCCM.<br>
powershell.exe -file "C:\Path\To\Script\Fix-log4j_jndi_7zip.ps1" -executionpolicy Bypass

Tested on Windows 10, Server 2012R2, 2016 and 2019.

<b>THE SCRIPT IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND.</b>



