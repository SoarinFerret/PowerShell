# Get-HyperVHost
Function Get-HyperVHost {
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    Invoke-command -ComputerName $ComputerName -ScriptBlock {
        return $(get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName") 
    }
}


# stolen from https://gallery.technet.microsoft.com/scriptcenter/Send-WOL-packet-using-0638be7b
function Send-WakeOnLan {
    <# 
    .SYNOPSIS  
    Send a WOL packet to a broadcast address
    .PARAMETER mac
    The MAC address of the device that need to wake up
    .PARAMETER ip
    The IP address where the WOL packet will be sent to
    .EXAMPLE 
    Send-WOL -mac 00:11:32:21:2D:11 -ip 192.168.8.255 
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$MAC,
        [string]$IP="255.255.255.255", 
        [int]$Port=9
    )   
    $broadcast = [Net.IPAddress]::Parse($ip)
    $mac=(($mac.replace(":","")).replace("-","")).replace(".","")
    $target=0,2,4,6,8,10 | ForEach-Object {[convert]::ToByte($mac.substring($_,2),16)}
    $packet = (,[byte]255 * 6) + ($target * 16)
    $UDPclient = new-Object System.Net.Sockets.UdpClient
    $UDPclient.Connect($broadcast,$port)
    [void]$UDPclient.Send($packet, 102) 
}


# TODO: add option to send to different computer
function Invoke-TextToSpeech {
    param ([Parameter(Mandatory=$true, ValueFromPipeline=$true)] [string] $Text)
    [Reflection.Assembly]::LoadWithPartialName('System.Speech') | Out-Null   
    $object = New-Object System.Speech.Synthesis.SpeechSynthesizer 
    $object.Speak($Text) 
}

# Checks windows installer for what version of windows it contains
function Get-WindowsInstaller {
    param (
        [Parameter(Position=0,Mandatory=$true)][String]$DriveLetter
    )
    Test-Admin
    if(!(Get-Volume $DriveLetter[0] -ErrorAction SilentlyContinue)){throw "Volume with the property 'DriveLetter' equal to '$($DriveLetter[0])' cannot be found"}
    $file = "install.wim"
    if(Test-Path "$($DriveLetter[0]):\sources\install.esd"){ $file = "install.esd"}
    for($index = 1; $index -ne 0; $index++){
        $a = dism /Get-WimInfo /WimFile:$($DriveLetter[0])`:\sources\$file /index:$index | Select-String -Pattern "Name" -SimpleMatch
        
        if($a -ne $null){ write-host $a.ToString().SubString(7) }
        else { $index = -1 }
    }
}

# Useful on older versions of powershell
function Test-Admin {
    $admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (!($admin)){
        throw "You are not running as an administrator"
    }
    else {
        Write-Verbose "Got admin"
        return $true
    }
}

# Create Bsod
function Invoke-Bsod{
    Param(
        [String]$Computername = $env:COMPUTERNAME,
        [Pscredential]$Credential
    )
    Write-Host "This will cause a Blue Screen of Death on $Computername.`nAre you sure absolutely sure you want to proceed? (y/n): " -ForegroundColor Red -NoNewline
    $confirm = Read-Host 
    if ($confirm -notlike "y*") {
        return 0;
    }

    # splat invoke-command
    $params = @{}
    if ($computername -notlike $env:COMPUTERNAME -and `
        $ComputerName -notlike "localhost"){
        $params['ComputerName'] = $ComputerName
    }
    if ($Credential){ $params['Credential'] = $Credential }

    Invoke-Command @params -ScriptBlock {
        wmic process where processid!=0 call terminate
    }

}

#############################################################################################################
#
#                                        Modern Authentication O365
#
#############################################################################################################

# connect to exchangeonline using modern authentication or basic
function Connect-ExchangeOnline {
    Param(
        [String]$UserPrincipalName = "",
        [PSCredential]$Credential = $null,
        [String]$ConnectionURI = 'https://outlook.office365.com/PowerShell-LiveId',
        [switch]$UseBasic
    )
    $PSSession = $null

    # Check if Exchange Online PowerShell module is installed, otherwise revert to old way
    $Module = "Microsoft.Exchange.Management.ExoPowershellModule.dll"
    if(!$UseBasic -and ($ModulePath = (Get-ChildItem $env:LOCALAPPDATA\Apps -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -like $Module -and $_.DirectoryName -like "*tion*"}))){
        $ModulePath= $ModulePath[0].FullName
        $global:ConnectionUri = $ConnectionUri
        $global:AzureADAuthorizationEndpointUri = 'https://login.windows.net/common'
        $global:UserPrincipalName = $UserPrincipalName
        Import-Module $ModulePath
        $PSSession = New-ExoPSSession -UserPrincipalName $UserPrincipalName -ConnectionUri $ConnectionUri -AzureADAuthorizationEndpointUri $AzureADAuthorizationEndpointUri
    }
    else{
        $PSSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionURI -AllowRedirection -Credential $Credential -Authentication Basic
    }
    if ($null -ne $PSSession) { Import-PSSession $PSSession -AllowClobber }
}

# connect to the security and compliance center using modern or basic authentication
function Connect-SecurityAndComplianceCenter {
    Param(
        $UserPrincipalName = "",
        [PSCredential]$Credential = $null,
        $ConnectionURI = 'https://ps.compliance.protection.outlook.com/PowerShell-LiveId',
        [switch]$UseBasic
    )
    $param = @{UserPrincipalName=$UserPrincipalName;Credential=$Credential;ConnectionURI=$ConnectionURI;UseBasic=$UseBasic}
    Connect-ExchangeOnline @param
}