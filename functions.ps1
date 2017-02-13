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
