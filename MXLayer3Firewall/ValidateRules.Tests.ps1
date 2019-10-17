set-location $PSScriptRoot

if(-not(get-module -ListAvailable -Name Pester))
{
    Install-Module -Name Pester -Force -RequiredVersion 4.9.0
}

$AllowedVlanNames = @("DATA","VOICE","GUEST_WIRED","CLOUD-MGT","CKNMOBILE","CKNGUEST")
. $PSScriptRoot\helpers.ps1
$defaultAnySourceRules = (Get-Content -Path '.\config\default-any-source-rules.json' -Raw) | ConvertFrom-Json
$defaultNetworkRulesPerVlan = (Get-Content -Path '.\config\default-network-rules-per-vlan.json' -Raw) | ConvertFrom-Json

describe "Test Default Any source Rules" {

    foreach($rule in $defaultAnySourceRules)
    {
        it "rule $($rule.comment) rule validation check" {

            { [MXLayer3FirewallRule] $DefaultAnySourceRule = [MXLayer3FirewallRule]::new(
                $rule.comment,
                $rule.policy,
                $rule.protocol,
                $rule.srcPort,
                $rule.srcCidr,
                $rule.destPort,
                $rule.destCidr,
                $rule.syslogEnabled
            )
            } | should not throw
        }
    }
}

Describe "Test Default Network rules per vlan" {

    foreach($rule in $defaultNetworkRulesPerVlan)
    {
        it "rule $($rule.comment) src vlan name check" {

            $AllowedVlanNames | should -Contain $rule.srcVlanName
        }

        it "rule $($rule.comment) rule validation check" {
            { 
                [MXLayer3FirewallRule] $VlanSpecificGenericRule = [MXLayer3FirewallRule]::new(
                    $rule.comment,
                    $rule.policy,
                    $rule.protocol,
                    $rule.srcPort,
                    "10.1.1.1/32",
                    $rule.destPort,
                    $rule.destCidr,
                    $rule.syslogEnabled  
                )
            } | should not throw 
        }
    }
}

$networkSpecificRules = Get-ChildItem -path "$PSScriptRoot\config" -Directory

foreach($config in $networkSpecificRules)
{
    Describe "Testing Network $($config.Name) specific rules" {
        $networkRules = (Get-Content -Path "$($config.FullName)\rules.json" -Raw) | ConvertFrom-Json
    
        foreach($rule in $networkRules)
        {
            it "network $($config.Name) specific rule $($rule.comment) - rule valid" {
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
                } | should not throw
            }
        }
    }
}