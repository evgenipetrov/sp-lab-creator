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
        [string]$Command
    )

    $registryKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $keyExists = Test-Path $registryKey

    if(-Not $keyExists){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\" -Name "RunOnce"
    }
        
    Set-ItemProperty -Path $registryKey -Name "NextRun" -Value $Command
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
    $adComputer = Get-ADComputer -Identity $env:COMPUTERNAME

    if($adComputer -eq $null){

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
    -NoRebootOnCompletion:$false `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Force:$true `
    -SafeModeAdministratorPassword $secureString
    }
}

function Add-LabServiceAccounts{
    param(
        [string]$Password
    )
    
    $usernames = @('sql_service',
                   'sp_farm')

    foreach($username in $usernames){
        $userPrincipalName = $username +"@" + $env:USERDNSDOMAIN.ToLower() 
        $accountPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

        try{
            Get-ADUser -Identity $username -ErrorAction SilentlyContinue
        }
        catch{
            New-ADUser -Name $username -UserPrincipalName $userPrincipalName -AccountPassword $accountPassword -PasswordNeverExpires:$true -ChangePasswordAtLogon:$false -Enabled:$true
        }
    }
}

function Add-LabDatabase{
    param(
        [string]$Username,
        [string]$Password
    )

    $path = $PSScriptRoot + "\iso\sql"
    $iso = Get-ChildItem -Path $path

    $mountResult = Mount-DiskImage -ImagePath $iso.FullName -PassThru
    $drive = $mountResult | Get-Volume

    $setup = "$($drive.driveletter):\setup.exe"

    $sqlsysadminaccounts = $env:USERDOMAIN + "\" + $env:USERNAME

    $command = "cmd /c $setup /ACTION=Install /IACCEPTSQLSERVERLICENSETERMS /FEATURES=SQLEngine,ADV_SSMS /INSTANCENAME=MSSQLSERVER /Q /SQLSVCACCOUNT=$Username /SQLSVCPASSWORD=$Password /INDICATEPROGRESS /SQLSYSADMINACCOUNTS=$sqlsysadminaccounts"
    Invoke-Expression -Command:$command

    #Dismount-DiskImage -DevicePath $drive
}