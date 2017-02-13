#variables
$username = $env:USERDOMAIN + "\" + $env:USERNAME
$password = "demo!234"
$computername = "SP2013"

$domainName = "CONTOSO.COM"
$domainNetbiosName = "CONTOSO"
$safemodeAdministratorPassword = "demo!234"


#import funstions
. "$PSScriptRoot\functions.ps1"

#tasks

# 1. add current script to run once on current user logon
$file = Get-LabScriptFile
$command = "$PSHome\powershell.exe -File " + $file.FullName
Set-LabRunOnce -Command $command

# 2. enable automatic logon with current user
Set-LabAutologon -Username $username -Password $password

# 3. rename computer and reboot
Rename-LabComputer -NewName $computername

# 4. install active directory
Install-LabActiveDirectoryServices -DomainName $domainName -DomainNetbiosName $domainNetbiosName -SafeModeAdministratorPassword $safemodeAdministratorPassword
