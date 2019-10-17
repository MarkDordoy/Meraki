[cmdletbinding()]
param
(
    [parameter(Mandatory)]
    [string]$ApiKey,

    [parameter(Mandatory=$false)]
    [string[]]$TargetNetworks = "*",

    [parameter(Mandatory=$false)]
    [string]$ApiVersion = "v0",

    [parameter(Mandatory=$false)]
    [ValidateSet("DryRun","Apply")]
    [string]$Mode = "DryRun"
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

Write-Information "Starting Meraki Layer 3 Firewall Rules deployment"
Write-Information "Running in $Mode mode"

$baseUrl = Get-MerakiBaseUrl -ApiKey $ApiKey -ApiVersion $ApiVersion

#Getting Organisation and all networks from organisation
$organisation = Invoke-RestMethod -Method Get -Uri "$baseUrl/organizations" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec
$networks = Invoke-RestMethod -Method Get -Uri "$baseUrl/organizations/$($organisation.id)/networks" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec

#Getting all rules from default-any-source-rules.json
$defaultAnySourceRules = (Get-Content -Path '.\config\default-any-source-rules.json' -Raw) | ConvertFrom-Json
#Getting all rules from default-network-rules-per-vlan.json
$defaultNetworkRulesPerVlan = (Get-Content -Path '.\config\default-network-rules-per-vlan.json' -Raw) | ConvertFrom-Json

#Creating an empty list used to contain all the config (folders from config file) that we want to target. Either all (*) or comma seperated list
$networkConfigRulesList = New-Object System.Collections.ArrayList
if($TargetNetworks -eq "*")
{
    #Loops through all folders in the config folder and adds the names to the list $networkConfigRulesList
    Write-Information "Running against all networks"
    $networkConfigs = Get-ChildItem -path "$PSScriptRoot\config" -Directory
    foreach($config in $networkConfigs)
    {
        [void]$networkConfigRulesList.Add($config.Name)
    }
}
else 
{
    #Adds each specific network name to the list $networkConfigRulesList
    Write-Information "Running against the specific networks $TargetNetworks"
    foreach($network in $TargetNetworks)
    {
        [void]$networkConfigRulesList.Add($network)
    }
}

#Looping though each network in the list defined above $networkConfigRulesList
foreach($network in $networkConfigRulesList)
{
    Write-Verbose "Checking rules for network $network"
    #Creates an empty list. This list will contain all rules we need to apply against the Meraki network
    $listOfnewRulesToApply = New-Object System.Collections.Generic.List[MXLayer3FirewallRule]
    $networkDetails = $networks | Where-Object {$_.name -eq $network}

    #Calls a function to check the specific network has its own specific rules.json file. If it doesnt it skips this network
    $networkSpecificRules =  Test-NetworkSpecificRuleExists -Path "$PSScriptRoot\config\$network" -NetworkName $network
    if($networkSpecificRules -eq $false)
    {
        continue
    }

    $networkRules = (Get-Content -Path ".\config\$network\rules.json" -Raw) | ConvertFrom-Json
    #If networkdetails is empty it skips this network. It will mean you have a config in the repo, but the meraki org doesnt have a network with the same name
    if($null -eq $networkDetails)
    {
        Write-Warning "We have a network config for $network but we are unable to find a network matching that name in the meraki organisation, skipping this network"
        continue
    }
    
    #Gets all the vlans for the current network
    $vlans = Invoke-RestMethod -Method Get -Uri "$baseUrl/networks/$($networkDetails.id)/vlans" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec

    #Loops through each rule in the file default-any-source-rules.json. Creates an object that represents the rule and adds it to the list $listOfnewRulesToApply
    foreach($rule in $defaultAnySourceRules)
    {
        try 
        {
            [MXLayer3FirewallRule] $DefaultAnySourceRule = [MXLayer3FirewallRule]::new(
                $rule.comment,
                $rule.policy,
                $rule.protocol,
                $rule.srcPort,
                $rule.srcCidr,
                $rule.destPort,
                $rule.destCidr,
                $rule.syslogEnabled,
                $true
            )
        }
        catch {
            write-warning "Unable to apply Default any rule $($rule.comment). $_"
            Write-Warning "Skipping rule"
            continue
        }

        [void]$listOfnewRulesToApply.Add($defaultAnySourceRule)                
    }

    #Loops through each rule in the file default-network-rules-per-vlan.json. Creates an object that represents the rule and adds it to the list $listOfnewRulesToApply
    # It updates the srcCidr based on the files value. The value is used to match a vlan in network. On a successful match the cidr range is injected into the rule and added
    #to the list
    foreach($rule in $defaultNetworkRulesPerVlan)
    {
        $vlanDetails = $vlans | Where-Object {$_.Name -eq $rule.srcVlanName}
        if($null -eq $vlanDetails)
        {
            #Skips rule if vlan name cannot be found in the network
            Write-Warning "The Default Network rule with comment $($rule.comment) had a srcCidr Name of $($rule.srcVlanName) that could not be matched to a vlan name in the network $network"
            Write-Warning "`nskipping this rule (see below), please fix if you want it applied to this network"
            $rule | ConvertTo-Json | Write-Warning
            continue
        }

        try 
        {
            [MXLayer3FirewallRule] $VlanSpecificGenericRule = [MXLayer3FirewallRule]::new(
                $rule.comment,
                $rule.policy,
                $rule.protocol,
                $rule.srcPort,
                $vlanDetails.subnet,
                $rule.destPort,
                $rule.destCidr,
                $rule.syslogEnabled  
            )    
        }
        catch {
            write-warning "Unable to apply Default vlan specific rule $($rule.comment) on vlan $($vlanDetails.Name). $_"
            Write-Warning "Skipping rule"
            continue  
        }
        
        [void]$listOfnewRulesToApply.Add($VlanSpecificGenericRule) 
    }

    #Loops through each rule in the rules.json file for the specific network. Each rules gets added to the list $listOfnewRulesToApply
    foreach($rule in $networkRules)
    {
        try 
        {
            [MXLayer3FirewallRule] $NetworkSpecificRule = [MXLayer3FirewallRule]::new(
                $rule.comment,
                $rule.policy,
                $rule.protocol,
                $rule.srcPort,
                $rule.srcCidr,
                $rule.destPort,
                $rule.destCidr,
                $rule.syslogEnabled  
            )    
        }
        catch 
        {
            write-warning "Unable to apply network specific rule $($rule.comment). $_"
            Write-Warning "Skipping rule"
            continue  
        }

        [void]$listOfnewRulesToApply.Add($NetworkSpecificRule)

    }
    
    #Adds the default deny all rule (will be penultimate) to list $listOfnewRulesToApply
    [MXLayer3FirewallRule] $MXLayer3DefaultDenyRule = [MXLayer3FirewallRule]::new("Deny")

    #Adds the default allow all rule to list $listOfnewRulesToApply. This rule is only added to aid in the compare. 
    [MXLayer3FirewallRule] $MXLayer3DefaultRule = [MXLayer3FirewallRule]::new("Default")

    [void]$listOfnewRulesToApply.Add($MXLayer3DefaultDenyRule)
    [void]$listOfnewRulesToApply.Add($MXLayer3DefaultRule)
    
    #Gets the current rules for the network
    $currentRules = Invoke-RestMethod -Method Get -Uri "$baseUrl/networks/$($networkDetails.id)/l3FirewallRules" -Headers $headers -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec
    
    #Builds the rules object into the extact structure the API requires 
    $NewRulesObject = @{"rules" = @($listOfnewRulesToApply)}
    $currentRulesObject = @{"rules" = @($currentRules)}

    $newRulesInJson = $NewRulesObject | ConvertTo-Json
    $currentRulesInJson = $currentRulesObject | ConvertTo-Json

    #Checks to see if the new rules are the same as the current rules. If they are skip to next network
    if($newRulesInJson -ieq $currentRulesInJson)
    {
        Write-Verbose "Current rules for network $network`n"
        Write-Verbose $currentRulesInJson
        Write-Verbose "`nRules generated based on config for network $network`n"
        Write-Verbose $newRulesInJson
        Write-Information "Network rules for network $network are already in the desired state, skipping."
        continue
    }
    else 
    {
        Write-Information "Current rules for network $network`n"
        Write-Information $currentRulesInJson
        Write-Information "`nRules for $network to be applied:`n"
        Write-Information $newRulesInJson

        if($Mode -eq "Apply")
        {
            #Remove the default allow all rule (Meraki adds this and does not want us to define. We only define so we can compare rules)
            $listOfnewRulesToApply.Remove($MXLayer3DefaultRule)
            $NewRulesObject = @{"rules" = @($listOfnewRulesToApply)}
            $newRulesInJson = $NewRulesObject | ConvertTo-Json

            Write-Information "Applying firewall rules for network $network"
            $result = Invoke-RestMethod -Method Put -Uri "$baseUrl/networks/$($networkDetails.id)/l3FirewallRules" -Headers $headers `
                                        -Body $newRulesInJson -MaximumRetryCount $maximumRetryCount -RetryIntervalSec $retryIntervalSec
            Write-Verbose "Verbose output from applying rules:`n"
            $result | out-string | write-verbose
            Write-Information "Network $network firewall rule applied"
        }
        else 
        {
            Write-Information "Mode set to dry run, network rule needs updating but you must set mode to 'apply'"    
        }  
    }
}