#variables
$username = $env:USERDOMAIN + "\" + $env:USERNAME
$password = "demo!234"
$computername = "SP2013"

$domainName = "CONTOSO.COM"
$domainNetbiosName = "CONTOSO"
$safemodeAdministratorPassword = $password

$dbServiceUser = 'SQL_Service'
$dbServicePassword = $password

$farmAccountUsername = "SP_Farm"
$farmAccountPassword = $password

$objectCacheSuperUserAccount = "SP_CacheSuperUser"
$objectCacheSuperUserPassword = $password

$objectCacheSuperReaderAccount = "SP_CacheSuperReader"
$objectCacheSuperReaderPassword = $password

$servicesAccount = "SP_Services"
$servicesAccountPassword = $password

$webApplicationAccount = "SP_PortalAppPool"
$webApplicationAccountPassword = $password

$mySitesAccount = "SP_ProfilesAppPool"
$mySitesAccountPassword = $password

$searchServiceApplicationAccount = "SP_SearchService"
$searchServiceApplicationAccountPassword = $password

$searchCrawlAccount = "SP_SearchContent"
$searchCrawlAccountPassword = $password



#import funstions
. "$PSScriptRoot\functions.ps1"

#tasks

# 1. add current script to run once on current user logon
$file = Get-LabScriptFile
$command = "$PSHome\powershell.exe -NoExit -File " + $file.FullName
Set-LabRunOnce -Command $command

# 2. enable automatic logon with current user
Set-LabAutologon -Username $username -Password $password

# 3. rename computer and reboot
Rename-LabComputer -NewName $computername

# 4. install active directory
$username = $domainName +"\" + $env:USERNAME
Set-LabAutologon -Username $username -Password $password
Install-LabActiveDirectoryServices -DomainName $domainName -DomainNetbiosName $domainNetbiosName -SafeModeAdministratorPassword $safemodeAdministratorPassword

# 5. create service accounts
Add-LabServiceAccount -Username $dbServiceUser -Password $dbServicePassword
Add-LabServiceAccount -Username $farmAccountUsername -Password $farmAccountPassword
Add-LabServiceAccount -Username $objectCacheSuperUserAccount -Password $objectCacheSuperUserPassword
Add-LabServiceAccount -Username $objectCacheSuperReaderAccount -Password $objectCacheSuperReaderPassword
Add-LabServiceAccount -Username $servicesAccount -Password $servicesAccountPassword
Add-LabServiceAccount -Username $webApplicationAccount -Password $webApplicationAccountPassword
Add-LabServiceAccount -Username $mySitesAccount -Password $mySitesAccountPassword
Add-LabServiceAccount -Username $searchServiceApplicationAccount -Password $searchServiceApplicationAccountPassword
Add-LabServiceAccount -Username $searchCrawlAccount -Password $searchCrawlAccountPassword

# 5. install database
$dbServiceUser = $env:USERDOMAIN +"\" + $dbServiceUser
Add-LabDatabase -Username $dbServiceUser -Password $dbServicePassword

# 6. install sharepoint
$farmAccountUsername = $env:USERDOMAIN +"\" + $farmAccountUsername
$objectCacheSuperUserAccount = $env:USERDOMAIN +"\" + $objectCacheSuperUserAccount
$objectCacheSuperReaderAccount = $env:USERDOMAIN +"\" + $objectCacheSuperReaderAccount
$servicesAccount = $env:USERDOMAIN +"\" + $servicesAccount
$webApplicationAccount = $env:USERDOMAIN +"\" + $webApplicationAccount
$mySitesAccount = $env:USERDOMAIN +"\" + $mySitesAccount
$searchServiceApplicationAccount = $env:USERDOMAIN +"\" + $searchServiceApplicationAccount
$searchCrawlAccount = $env:USERDOMAIN +"\" + $searchCrawlAccount



Add-LabSharePoint -SharePointVersion 2013 -AutoLogon:$true -SKU Enterprise -ProductKey NQTMW-K63MQ-39G6H-B2CH9-FRDWJ -FarmPassPhrase $password -DatabaseServerInstance localhost `
    -FarmAccountUsername $farmAccountUsername -FarmAccountPassword $password `
    -ObjectCacheSuperUserAccount $objectCacheSuperUserAccount `
    -ObjectCacheSuperReaderAccount $objectCacheSuperReaderAccount `
    -ServicesAccount $servicesAccount -ServicesAccountPassword $password `
    -WebApplicationAccount $webApplicationAccount -WebApplicationAccountPassword $password `
    -MySitesAccount $mySitesAccount -MySitesAccountPassword $password `
    -SearchServiceApplicationAccount $searchServiceApplicationAccount -SearchServiceApplicationAccountPassword $password `
    -SearchCrawlAccount $searchCrawlAccount -SearchCrawlPassword $password 


