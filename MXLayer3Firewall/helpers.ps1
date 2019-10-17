$ErrorActionPreference = "stop"
$InformationPreference = "Continue"

Function Test-NetworkSpecificRuleExists
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [string]$Path,
        [parameter(Mandatory)]
        [string]$NetworkName
    )

    if(-not(Test-Path -Path "$Path/rules.json"))
    {
       Write-Warning "No rules.json found for network $NetworkName... skipping"
       return $false
    }
    else 
    {
        return $true    
    }
}

Function Test-PSVersion
{
    [cmdletbinding()]
    param
    ()
    
    If($PSVersionTable.PSEdition -ne "core")
    {
        Write-Error "Please run this in a PS Core shell"
    }
}

Function Get-MerakiBaseUrl
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [string]$ApiKey,

        [parameter(Mandatory)]
        [string]$ApiVersion 
    )

        $baseUrl = "https://api.meraki.com/api/$ApiVersion"
        $maximumRetryCount = 5
        $retryIntervalSec = 1

        $headers = @{
            "X-Cisco-Meraki-API-Key"=$ApiKey
            "Content-Type"="application/json"
            "Accept" = "*/*"
        }

        #Need to handle redirect as specified here https://documentation.meraki.com/zGeneral_Administration/Other_Topics/The_Cisco_Meraki_Dashboard_API
        $redirectUrl = Invoke-WebRequest -Method Head -Uri "$baseUrl/organizations" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec

        if($null -ne $redirectUrl.BaseResponse.RequestMessage.RequestUri)
        {
            return  "https://$($redirectUrl.BaseResponse.RequestMessage.RequestUri.Host)/api/$ApiVersion"
        }
        else 
        {
            Write-Warning "Unable to determine organisation base url, falling back to default"
            return $baseUrl    
        }
}

class MXLayer3FirewallRule 
{
    [ValidateNotNullOrEmpty()]
    [string] $comment

    [validateSet("allow","deny")]
    [string] $policy

    [validateSet("icmp","tcp","udp","any")]
    [string] $protocol

    [string] $srcPort

    [string] $srcCidr

    [string] $destPort

    [string] $destCidr

    [bool] $syslogEnabled

    #Default Contructor
    MXLayer3FirewallRule()
    {
        #Initialises the object to enforce order
        $this.comment = "Intialization Object"
        $this.policy = "deny"
        $this.protocol = "any"
        $this.srcPort = ""
        $this.srcCidr = ""
        $this.destPort = ""
        $this.destCidr = ""
        $this.syslogEnabled = $false
    }

    #Contructor to build a default or deny rule
    MXLayer3FirewallRule([string]$PreConfiguredRuleName)
    {
        if($PreConfiguredRuleName -eq "Default")
        {
            $this.SetDefaultRule()
        }
        elseif($PreConfiguredRuleName -eq "Deny")
        {
            $this.SetDefaultDenyRule()
        }
    }

    #Constructor to build a rule which should always have any for src port and cidr
    MXLayer3FirewallRule([string]$Comment,[string]$Policy,[string]$Protocol,[string]$SrcPort,[string]$SrcCidr,[string]$DestPort,[string]$DestCidr,[bool]$SyslogEnabled,[bool]$AnyRule)
    {
        $this.comment = $Comment
        $this.policy = $Policy.ToLower()
        $this.protocol = $Protocol.ToLower()
        $this.srcPort = $SrcPort.ToLower()
        $this.srcCidr = $SrcCidr.ToLower()
        $this.destPort = $DestPort.ToLower()
        $this.destCidr = $DestCidr.ToLower()
        $this.syslogEnabled = $SyslogEnabled

        try {
            $this.ValidateAnyRule($this.srcCidr,"Source CIDR")     
            $this.ValidateAnyRule($this.srcPort,"Source Port")  
        }
        catch {
            Write-verbose "Error on validateRule in MXLayer3FirewallRule Construtor for any source rule. $_" 
            throw $_
        }
    }

    #Constructor for standard rule
    MXLayer3FirewallRule([string]$Comment,[string]$Policy,[string]$Protocol,[string]$SrcPort,[string]$SrcCidr,[string]$DestPort,[string]$DestCidr,[bool]$SyslogEnabled)
    {
        $this.comment = $Comment
        $this.policy = $Policy.ToLower()
        $this.protocol = $Protocol.ToLower()
        $this.srcPort = $SrcPort.ToLower()
        $this.srcCidr = $SrcCidr.ToLower()
        $this.destPort = $DestPort.ToLower()
        $this.destCidr = $DestCidr.ToLower()
        $this.syslogEnabled = $SyslogEnabled

        try
        {
            $this.ValidateRule()
        }
        catch
        {
            Write-verbose "Error on validateRule in MXLayer3FirewallRule Construtor. $_" 
            throw $_
        }
    }

    hidden [void]ValidateRule()
    {
       try {
        $this.ValidateCidr($this.destCidr)   
        $this.ValidateCidr($this.srcCidr)   
        $this.ValidatePort($this.destPort)
        $this.ValidatePort($this.srcPort)
       }
       catch {
           throw $_
       }
    }

    hidden [bool]ValidateAnyRule([string]$value,[string]$type)
    {
        if($value -ieq "any")
        {
            return $true
        }
        else 
        {
            throw "$type $value is not valid. $type rule must be set to 'Any'"
        }
    }

    hidden [bool]ValidateCidr([string]$cidrRange)
    {
        if($cidrRange -ieq "any")
        {
            return $true
        }
        elseif($cidrRange.Contains(','))
        {         
            $range = $cidrRange -split ","
            foreach($cidr in $range)
            {
                if($cidr -notmatch '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
                {
                    throw "Cidr range $cidr is not valid"
                }
            }
            return $true
        }
        else 
        {
            if($cidrRange -notmatch '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$')
            {
                throw "Cidr range $cidrRange is not valid"
            }
            return $true
        }
    }

    hidden [bool]ValidatePort([string]$PortRange)
    {
        if($PortRange -ieq "any")
        {
            return $true
        }
        elseif($PortRange.Contains(','))
        {
            $range = $PortRange -split ","
            foreach($port in $range)
            {
                if($port -notmatch '^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$')
                {
                    throw "Port number $port not valid"
                }
            }
            return $true
        }
        else 
        {
            $ports = $PortRange -split "-"  
            foreach($port in $ports)
            {  
                if($port -notmatch '^(6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}|0)$')
                {
                    throw "Port number $port not valid"
                }
            }
            return $true
        }
    }

    hidden [void]SetDefaultRule()
    {
        $this.comment = "Default rule"
        $this.policy = "allow"
        $this.protocol = "any"
        $this.srcPort = "any"
        $this.srcCidr = "any"
        $this.destPort = "any"
        $this.destCidr = "any"
        $this.syslogEnabled = $false
    }

    hidden [void]SetDefaultDenyRule()
    {
        $this.comment = "DENY ALL"
        $this.policy = "deny"
        $this.protocol = "any"
        $this.srcPort = "any"
        $this.srcCidr = "any"
        $this.destPort = "any"
        $this.destCidr = "any"
        $this.syslogEnabled = $true
    }
}