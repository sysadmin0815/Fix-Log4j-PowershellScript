# Fix-Log4j-PowershellScript
search and remove JNDI class from *log4j*.jar files on the system with Powershell (Windows) - defaults to C:\

7-Zip is used to delete the class in the jar file.
source: https://www.7-zip.org/

<b> Please read the script and modify it if needed before you execute it!</b>

execute the script with elevated Powershell.exe or with deploment tools like SCCM.<br>
powershell.exe -file "C:\Path\To\Script\Fix-log4j_jndi_7zip.ps1" -executionpolicy Bypass

Tested on Windows 10, Server 2012R2, 2016 and 2019.

<b>THE SCRIPT IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND.</b>



