#rename computer
function Rename-LabComputer{
    Param(
        [string]$NewName
    )

    if($env:COMPUTERNAME -ne $NewName){
        Rename-Computer -NewName $NewName -Restart
    }
}

#get current script name
function Get-LabScriptFile{

    $literalPath = $MyInvocation.PSCommandPath
    $file = Get-ChildItem -LiteralPath $literalPath
    Write-Output $file
}

function Set-LabRunOnce{
    param(
        [string]$Command,
        [bool]$Enabled=$true
    )
    $registryKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    if($Enabled -eq $true){

        $keyExists = Test-Path $registryKey

        if(-Not $keyExists){
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\" -Name "RunOnce"
        }
        
        Set-ItemProperty -Path $registryKey -Name "NextRun" -Value $Command
    
    } else {
        Remove-Item -Path $registryKey
    }
}

function Set-LabAutologon{
    param(
        [string]$username,
        [string]$password
    )

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUsername -Value $username
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $password
}

function Install-LabActiveDirectoryServices{
    param(
        [string]$DomainName,
        [string]$DomainNetbiosName,
        [string]$SafeModeAdministratorPassword
        
    )
    
    #install binaries
    $feature = Get-WindowsFeature -Name AD-Domain-Services
    if(-Not $feature.Installed){
        Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart
    }

    #promote domain controller
    try{
        $adComputer = Get-ADComputer -Identity $env:COMPUTERNAME
    }catch{
        $secureString = ConvertTo-SecureString -String $SafeModeAdministratorPassword -AsPlainText -Force
        Import-Module ADDSDeployment
        Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainMode "Win2012R2" `
        -DomainName $DomainName `
        -DomainNetbiosName $DomainNetbiosName `
        -ForestMode "Win2012R2" `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$true `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true `
        -SafeModeAdministratorPassword $secureString
        Restart-Computer
    }
}

function Add-LabServiceAccount{
    param(
        [string]$Username,
        [string]$Password
    )
    
        $userPrincipalName = $Username +"@" + $env:USERDNSDOMAIN.ToLower() 
        $accountPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

        try{
            Get-ADUser -Identity $Username -ErrorAction SilentlyContinue
        }
        catch{
            New-ADUser -Name $Username -UserPrincipalName $userPrincipalName -AccountPassword $accountPassword -PasswordNeverExpires:$true -ChangePasswordAtLogon:$false -Enabled:$true
        }

}

function Add-LabDatabase{
    param(
        [string]$Username,
        [string]$Password
    )

    try{
        $sqlService = Get-Service -Name MSSQLSERVER -ErrorAction Stop
    }
    catch{
        $path = $PSScriptRoot + "\iso\sql"
        $iso = Get-ChildItem -Path $path -Filter "*.iso"

        $mountResult = Mount-DiskImage -ImagePath $iso.FullName -PassThru
        $drive = $mountResult | Get-Volume

        $setup = "$($drive.driveletter):\setup.exe"

        $sqlsysadminaccounts = $env:USERDOMAIN + "\" + $env:USERNAME

        $command = "cmd /c $setup /ACTION=Install /IACCEPTSQLSERVERLICENSETERMS /FEATURES=SQLEngine,ADV_SSMS /INSTANCENAME=MSSQLSERVER /Q /SQLSVCACCOUNT=$Username /SQLSVCPASSWORD=$Password /INDICATEPROGRESS /SQLSYSADMINACCOUNTS=$sqlsysadminaccounts"
        Invoke-Expression -Command:$command

        Dismount-DiskImage -ImagePath $iso.FullName 
    }
  
}

function Add-LabSharePoint{
    param(
    [string]$SharePointVersion,
    [bool]$AutoLogon,
    [string]$SetupAccountPassword,
    [string]$SKU,
    [string]$ProductKey,
    [string]$FarmPassPhrase,
    [string]$DatabaseServerInstance,
    [string]$FarmAccountUsername,
    [string]$FarmAccountPassword,
    [string]$ObjectCacheSuperUserAccount,
    [string]$ObjectCacheSuperReaderAccount,
    [string]$ServicesAccount,
    [string]$ServicesAccountPassword,
    [string]$WebApplicationAccount,
    [string]$WebApplicationAccountPassword,
    [string]$MySitesAccount,
    [string]$MySitesAccountPassword,
    [string]$SearchServiceApplicationAccount,
    [string]$SearchServiceApplicationAccountPassword,
    [string]$SearchCrawlAccount,
    [string]$SearchCrawlPassword
    )



    try{
        $timerService = Get-Service -Name SPTimerv4 -ErrorAction Stop
    }
    catch{
        $path = $PSScriptRoot + "\iso\sharepoint"
        $iso = Get-ChildItem -Path $path -Filter "*.iso"

        $autospinstaller = $PSScriptRoot + "\scripts\AutoSPInstaller"

        # Move-Item -Path $autospinstaller -Destination "c:\"

        $mountResult = Mount-DiskImage -ImagePath $iso.FullName -PassThru
        $drive = $mountResult | Get-Volume

        $sharepointInstall = "$($drive.driveletter):\"

        # Get-ChildItem -Path $sharepointInstall -Recurse | Copy-Item -Destination "C:\AutoSPInstaller\sp\2013\SharePoint\" -Recurse -Force
        Get-ChildItem -Path $sharepointInstall -Recurse | Copy-Item -Destination "$autospinstaller\sp\$SharePointVersion\SharePoint\" -Recurse -Force

        Dismount-DiskImage -ImagePath $iso.FullName 

        $path = $autospinstaller + "\SP\AutoSPInstaller\AutoSPInstallerInput.xml"
        [xml]$autospinstallerConfig = Get-Content -Path $path

        $autospinstallerConfig.Configuration.Install.AutoAdminLogon.Password = $SetupAccountPassword

        $autospinstallerConfig.Configuration.Install.PIDKey = $ProductKey
        $autospinstallerConfig.Configuration.Farm.Passphrase = $FarmPassPhrase

        $autospinstallerConfig.Configuration.Farm.Database.DBAlias.DBInstance = $DatabaseServerInstance
        $autospinstallerConfig.Configuration.Farm.Database.DBAlias.Create = "false"

        $autospinstallerConfig.Configuration.Install.AutoAdminLogon.Enable = "true"
        $autospinstallerConfig.Configuration.Farm.Account.Username = $FarmAccountUsername
        $autospinstallerConfig.Configuration.Farm.Account.Password = $FarmAccountPassword

        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='spservice']").Node.Username = $ServicesAccount
        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='spservice']").Node.Password = $password

        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='Portal']").Node.Username = $WebApplicationAccount
        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='Portal']").Node.Password = $password

        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='MySiteHost']").Node.Username = $MySitesAccount
        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='MySiteHost']").Node.Password = $password

        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='SearchService']").Node.Username = $SearchServiceApplicationAccount
        (Select-Xml -Xml $autospinstallerConfig -XPath "//ManagedAccount[@CommonName='SearchService']").Node.Password = $password

        $autospinstallerConfig.Configuration.Farm.ObjectCacheAccounts.SuperUser = $ObjectCacheSuperUserAccount
        $autospinstallerConfig.Configuration.Farm.ObjectCacheAccounts.SuperReader = $ObjectCacheSuperReaderAccount

        $autospinstallerConfig.Configuration.ServiceApps.EnterpriseSearchService.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount = $SearchCrawlAccount
        $autospinstallerConfig.Configuration.ServiceApps.EnterpriseSearchService.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccountPassword = $SearchCrawlPassword

        $xmlFile = Resolve-Path $path
        $autospinstallerConfig.Save($xmlFile.Path)

        $autospinstallerLauncher = (Get-ChildItem $xmlFile.Path).DirectoryName + "\AutoSPInstallerLaunch.bat"

        $command = "cmd /c $autospinstallerLauncher"
        Invoke-Expression -Command:$command

    }
}