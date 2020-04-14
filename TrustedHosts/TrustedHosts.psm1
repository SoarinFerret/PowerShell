#############################################################################################################
#
#                                        Windows Trusted Hosts
#
#############################################################################################################
function Add-TrustedHost {
    Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
    [String[]]$ComputerName #for example, dc-cluster1 or 10.0.0.25
    )#end param
    process{ forEach($c in $ComputerName) { Set-Item WSMan:\localhost\Client\TrustedHosts -Value $c -Force -Concatenate } }
}

function Get-TrustedHost {
    Param(
    [Parameter(Position=0,ValueFromPipeline=$true)]
    [String[]]$ComputerName = "*"#for example, dc-cluster1 or 10.0.0.25
    )#end param
    process{ forEach($c in $ComputerName){ (Get-Item WSMan:\localhost\Client\TrustedHosts).Value.Split(',') | Where-Object {$_ -like "*$c*"} }}
}

function Remove-TrustedHost {
    Param(
    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
    [String[]]$ComputerName #for example, dc-cluster1 or 10.0.0.25
    )#end param
    process{
        forEach($c in $ComputerName){
            if((Get-TrustedHost $c) -eq $c) {
                $TrustedHosts = ""
                (Get-TrustedHost).Replace("$c","") | ForEach-Object {if($_ -ne "") {$TrustedHosts += $_ + ","}}
                Set-Item WSMan:\localhost\Client\TrustedHosts $TrustedHosts.TrimEnd(",") -Force
            }
        }
    }
}

