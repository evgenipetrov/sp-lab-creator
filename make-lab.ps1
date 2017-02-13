#variables
$computername = "SP2013"

#tasks

#rename computer
Rename-Computer -NewName $computername -Restart
