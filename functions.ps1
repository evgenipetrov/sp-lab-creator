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
    
    #install binaries
    $feature = Get-WindowsFeature -Name AD-Domain-Services
    if(-Not $feature.Installed){
        Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart
    }

    #install AD

}