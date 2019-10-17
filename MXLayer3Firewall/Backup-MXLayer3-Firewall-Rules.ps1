[cmdletbinding()]
param
(
    [parameter(Mandatory)]
    [string]$ApiKey,

    [parameter(Mandatory=$false)]
    [string]$ApiVersion = "v0",

    [parameter(Mandatory=$false)]
    [string[]]$TargetNetworks = "*"
)

$ErrorActionPreference = "stop"
$InformationPreference = "continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
set-location $PSScriptRoot

. $PSScriptRoot\helpers.ps1 # Loading in helper functions and class

Test-PSVersion

$baseUrl = "https://api.meraki.com/api/$ApiVersion"
$maximumRetryCount = 5
$retryIntervalSec = 1

$headers = @{
    "X-Cisco-Meraki-API-Key"=$ApiKey
    "Content-Type"="application/json"
    "Accept" = "*/*"
}

Write-Information "Starting Meraki Layer 3 Firewall Rules backup"

$baseUrl = Get-MerakiBaseUrl -ApiKey $ApiKey -ApiVersion $ApiVersion
$tempDir = [IO.Path]::GetTempPath()
$folderPostFix = get-date -Format "yyyyMMdd-HHmm"
$tempDir = "$tempDir\MXLayer3Backup_$folderPostFix"

if (-not(Test-Path -Path "$tempDir"))
{
    New-Item -Path "$tempDir" -ItemType Directory | Out-Null
}

$organisation = Invoke-RestMethod -Method Get -Uri "$baseUrl/organizations" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec
$networks = Invoke-RestMethod -Method Get -Uri "$baseUrl/organizations/$($organisation.id)/networks" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec

Write-Information "backup files saved to directory $tempDir"
Write-Host "##vso[task.setvariable variable=backupDir]$tempDir"
Write-Host "##vso[task.setvariable variable=backupFolderName]MXLayer3Backup_$folderPostFix"

$targetNetwork = New-Object System.Collections.Generic.List[object]
if($TargetNetworks -ne "*")
{
    foreach($network in $TargetNetworks)
    {
        $networkDetail = $networks | Where-Object {$_.Name -eq $network}
        if($null -eq $networkDetail)
        {
            Write-Error "Unable to find the network $Network in the current organisation. Please check the name"
        }
        $targetNetwork.add($networkDetail)
    }
}
else 
{
    foreach($network in $networks)
    {
        $targetNetwork.add($network)
    }
}

foreach($network in $targetNetwork)
{
    $currentNetworkRule = Invoke-RestMethod -Method Get -Uri "$baseUrl/networks/$($network.id)/l3FirewallRules" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec
    $RuleObject = New-Object System.Collections.Generic.List[MXLayer3FirewallRule]
    foreach($rule in $currentNetworkRule)
    {
        try 
        {
            [MXLayer3FirewallRule]$ruleInstanceObject = [MXLayer3FirewallRule]::new(
                $rule.comment,
                $rule.policy,
                $rule.protocol,
                $rule.srcPort,
                $rule.srcCidr,
                $rule.destPort,
                $rule.destCidr,
                $rule.syslogEnabled
            )
            $RuleObject.Add($ruleInstanceObject)
        }
        catch 
        {
            Write-Error "Please check rule outputed below. Failing to initialise an MXLayer3FirewallRule object" -ErrorAction SilentlyContinue
            $rule | out-string | Write-Error   
        }

    }

    #This removed the last object in the rule (the default allow all rule)
    $RuleObject.RemoveAt($RuleObject.Count-1)

    $currentRulesObject = @{"rules" = @($RuleObject)}
    $currentRulesInJson = $currentRulesObject | ConvertTo-Json
    $currentRulesInJson | out-file "$tempDir\$($network.id)_rules.json"
    Write-Information "Saved MX Layer 3 Rule for Network $($network.name), id $($network.id)"
}