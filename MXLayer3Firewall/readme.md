# Apply MX Layer3 Firewall Rules

The purpose of the file `Apply-MXLayer3-Firewall-Rules.ps1` is to read the config defined under the config directory to the matching meraki networks.

The flow of the script is to iterate over each network in the Clarksons Meraki organisation (this can be changed to target specific networks). For each network
in the organisation it will build up the rules in the following order:

1. Add all the rules in default-any-source-rules.json (these get applied to all networks)
2. Add all the rules in default-network-rules-per-vlan.json. These get applied to all networks, however the source Cidr is dynamically set. It asks Meraki for the Subnet of the vlan by mapping the srcVlanName value to the vlans name within meraki.
3. It then applies the custom rules only for the specific network. These rules are found in the config directory, under a folder who's name matches that of the network in meraki. The rules file must be called rules.json
4. Add the deny any rule
5. Add the allow any rule (Rule added by Meraki as default)

The order of the rules follow the order placed in the files in the order of flow as described above.

The nework must exist in meraki and have a folder named the same in the config for the script to run against it.

Once used in a pipeline, the config associated with this script should be seen as the desired state for the Meraki system in terms for Layer 3 Firewalls. Any changes made directly to the portal, if not then updated 
in the config to match, will get remove next time this script is run.

## MX Layer 3 Script Running Modes

The script by default runs in `dryRun` mode. This means it will run and build up the rules and compare, letting you know if there is a difference between configuration and what meraki has. However it will not change anything in Meraki.

To make the script apply you need to pass the arguement `-Mode "Apply"` to have it actually make changes to meraki

## Targeting specific Networks

By default the script will target all networks under an organisation. However if you want to limit it to only run against one or a few networks this can be done by passing a parameter. 

Example:

`-TargetNetworks "Network1"`

`-TargetNetworks "Network1","Network2","NetworkN"`

## Prerequisite to run

The script relies on having an internet connection over https port 443. The script also must be run in a powershell core shell

## Running the script

The script can be run in a powershellcore shell on either windows or linux. Once in the shell you can target the script to run as follows:

```powershell
# Example 1 - Runs in dry run mode against all networks
PS> c:\code\Networks\MXLayer3Firewall\Apply-MXLayer3-Firewall-Rules.ps1 -ApiKey "ftrgregregeret34tgfdge" 

#Example 2 - Runs in apply mode against all networks
PS> c:\code\Networks\MXLayer3Firewall\Apply-MXLayer3-Firewall-Rules.ps1 -ApiKey "ftrgregregeret34tgfdge" -Mode "Apply"

#Example 3 - Runs in dry mode against specific networks
PS> c:\code\Networks\MXLayer3Firewall\Apply-MXLayer3-Firewall-Rules.ps1 -ApiKey "ftrgregregeret34tgfdge" -TargetNetworks "Network1","Network2","Network3"

#Example 4 - Runs in apply mode against specific networks
PS> c:\code\Networks\MXLayer3Firewall\Apply-MXLayer3-Firewall-Rules.ps1 -ApiKey "ftrgregregeret34tgfdge" -TargetNetworks "Network1","Network2","Network3" -Mode "Apply"

```

## MX Layer 3 Backups

tbc