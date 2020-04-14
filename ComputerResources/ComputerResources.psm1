#############################################################################################################
#
#                                             Resources
#
#############################################################################################################

function Get-ComputerUptime {
    Param(
        [String]$ComputerName = "localhost",
        [pscredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName
    $bootuptime = (Get-CimInstance Win32_OperatingSystem -CimSession $session).LastBootUpTime
    $uptime = (date) - $bootuptime
    return New-Object psobject -Property @{"UpTime"=$uptime;"LastBootUpTime"=$bootuptime}
}

function Get-ComputerMemoryUtilization {
    Param(
        [String]$ComputerName = "localhost",
        [PSCredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName
    Get-CimInstance Win32_OperatingSystem -CimSession $session | `
    Select-Object @{Name = "FreeGB";Expression = {[math]::Round($_.FreePhysicalMemory/1mb,2)}},@{Name = "TotalGB";Expression = {[int]($_.TotalVisibleMemorySize/1mb)}}
}

function Get-ComputerCpuUtilization {
    Param(
        [String]$ComputerName = "Localhost",
        [PSCredential]$Credential
    )
    if ($Credential){
        $PSDefaultParameterValues = $PSDefaultParameterValues.clone()
        $PSDefaultParameterValues['*:Credential'] = $Credential
    }
    $session = New-CimSession -ComputerName $ComputerName    
    Get-CimInstance win32_processor -CimSession $session | Measure-Object -property LoadPercentage -Average | Select-Object Average
}

Function Get-ComputerUtilization{
    Param(
        [String]$ComputerName = $env:COMPUTERNAME,
        [PSCredential]$Credential,
        [ValidateSet("CPU","RAM","ID")]
        [String]$Sort = "CPU",
        [int]$Size = 15,
        [Switch]$Continue
    )
    
    # splat the computername and credential. 'Invoke-Command' is
    # much quicker if computername is not specified on localhost

    $credHash = @{}
    if ($computername -notlike $env:COMPUTERNAME -and `
        $ComputerName -notlike "localhost"){
        $credHash['ComputerName'] = $ComputerName
    }
    if ($Credential){ $credHash['Credential'] = $Credential }
    
    $s; switch($sort){
        "ID"  {$s = "ID"}
        "CPU" {$s = "CPU"}
        "RAM" {$s = "PM"}
    }
    do{
        Invoke-Command @credhash -ArgumentList $s,$size -ScriptBlock{
            Get-Process | Sort-Object -Descending $args[0] | Select-Object -First $args[1] | Format-Table
        }
        if($Continue){ Start-Sleep 1; Clear-Host; Write-Host "`n`t`t`tPress Ctrl-C to exit`n" -ForegroundColor Red }
    } while ($Continue)
}

#############################################################################################################
#
#                                              Aliases
#
#############################################################################################################

New-Alias Get-MemoryUsage Get-ComputerMemoryUtilization
New-Alias Get-CpuUsage Get-ComputerCpuUtilization
New-Alias pstop Get-ComputerUtilization