#variables
$computername = "SP2013"


#import funstions
. "$PSScriptRoot\functions.ps1"

#tasks
#add current script to run once
$file = Get-LabScriptFile
$command = "$PSHome\powershell.exe -File " + $file.FullName
Set-LabRunOnce -Command $command

#rename computer
Rename-LabComputer -NewName $computername


