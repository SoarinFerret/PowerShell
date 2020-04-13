Function Get-LinuxHypervKvpValues {
    <#
    .SYNOPSIS
    Retrive Hyper-V KVP Data Exchange values from a Linux based Hyper-V virtual machine.

    .DESCRIPTION
    Hyper-V provides key value pairs to VMs to send VM/Host info in a safe way. This function retrieves those key value pairs and returns them as a PowerShell object.

    .PARAMETER Path
    Location of the kvp_pool you would like to access. They are usually named .kvp_pool_x, where x is an integer between 0 and 4.

    .PARAMETER Session
    Optional parameter for a PSSession to remotely retrieve the KVP values.

    .EXAMPLE
    Get-LinuxHypervKvpValues -Session (New-PSSession -Hostname 192.168.1.1 -Username serveradmin)

    .NOTES
    Cody Ernesti
    github.com/soarinferret

    .LINK
    https://github.com/Soarinferret/PowerShell
    https://blog.kanto.cloud/retrieving-linux-hyper-v-kvps-in-powershell

    #>

    Param(
        [ValidateScript({Test-Path $_ -PathType 'Leaf'})] 
        [String]$Path = "/var/lib/hyperv/.kvp_pool_3",

        [Parameter(Mandatory=$false)]
        [ValidateScript({$_.State -eq "Opened"})] 
        [PsSession]$Session
    )
    function get-kvp ($KvpPath){
        $KEY_LENGTH = 512
        $VALUE_LENGTH = 2048

        $KVP_POOL = Get-Content $KvpPath -AsByteStream 

        $properties = @{}
        for($y = 0; $y -lt $KVP_POOL.Length; $y = $y + $KEY_LENGTH + $VALUE_LENGTH){

            $properties.add(
                # Key
                $([System.Text.Encoding]::UTF8.GetString($KVP_POOL[$y..$($y+$KEY_LENGTH -1)]) -replace "`0", ""),
                
                # Value
                $([System.Text.Encoding]::UTF8.GetString($KVP_POOL[$($y+$KEY_LENGTH)..$($y+$VALUE_LENGTH -1)]) -replace "`0", "")
            )
        }
        return New-Object PSObject -Property $properties
    }

    if($Session -and $Session.State -eq "Opened"){
        Invoke-Command -Session $Session -ScriptBlock ${function:get-kvp} -ArgumentList $Path
    }else{
        get-kvp $Path
    }
}
