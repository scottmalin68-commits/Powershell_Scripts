<#
================================================================================
AD Attack Path Shortener
================================================================================

GOAL
-----
Identify the shortest privilege‑escalation path from any AD user to Domain Admins
by analyzing group memberships and ACL‑based control relationships. Produce a
ranked list of “most dangerous users” based on path length and control depth.

AUDIENCE
---------
• Security engineers and IAM architects  
• AD administrators performing hardening reviews  
• Blue teams validating delegation and privilege boundaries  
• Auditors assessing privilege escalation exposure  

AUTHOR
-------
Scott M

LAST MODIFIED
--------------
2026‑01‑27

CHANGELOG
----------
v1.0.0  
• Initial release  
• Added documentation block  
• Added graph builder for groups and ACLs  
• Added shortest‑path engine  
• Added ranking model for dangerous users  

DESCRIPTION
------------
This script constructs a privilege‑escalation graph from Active Directory by
mapping:
• Group memberships  
• ACL‑based control rights (WriteOwner, GenericAll, WriteDacl, ExtendedRight)  
• Nested delegation chains  

It then computes the shortest path from every user to Domain Admins and outputs
a ranked list of users with the smallest number of hops required to escalate.

USAGE
------
Run in a privileged PowerShell session with RSAT installed:

    .\Invoke-ADAttackPathShortener.ps1

Outputs:
• Shortest path per user  
• Ranked list of highest‑risk users  
• Optional CSV/JSON export  

================================================================================
#>

param(
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

Write-Host "[+] Building AD privilege graph..."

# ---------------------------------------------------------------------------
# 1. COLLECT GROUP MEMBERSHIP DATA
# ---------------------------------------------------------------------------
$Groups = Get-ADGroup -Filter * -Properties Members
$GroupEdges = foreach ($g in $Groups) {
    foreach ($m in $g.Members) {
        [PSCustomObject]@{
            From = $m
            To   = $g.DistinguishedName
            Type = "GroupMembership"
        }
    }
}

# ---------------------------------------------------------------------------
# 2. COLLECT ACL-BASED CONTROL RELATIONSHIPS
# ---------------------------------------------------------------------------
Write-Host "[+] Collecting ACL rights..."

$ACLs = Get-ADObject -LDAPFilter "(objectClass=*)" -Properties ntSecurityDescriptor |
        ForEach-Object {
            $sd = $_.ntSecurityDescriptor
            foreach ($ace in $sd.Access) {
                if ($ace.ActiveDirectoryRights -match "WriteOwner|GenericAll|WriteDacl|ExtendedRight") {
                    [PSCustomObject]@{
                        From = $ace.IdentityReference
                        To   = $_.DistinguishedName
                        Type = "ACLControl"
                    }
                }
            }
        }

# ---------------------------------------------------------------------------
# 3. BUILD GRAPH
# ---------------------------------------------------------------------------
$Graph = $GroupEdges + $ACLs

Write-Host "[+] Graph built. Total edges:" $Graph.Count

# ---------------------------------------------------------------------------
# 4. SHORTEST PATH ENGINE
# ---------------------------------------------------------------------------
function Get-ShortestPath {
    param(
        [string]$Start,
        [string]$Target
    )

    $Queue = New-Object System.Collections.Queue
    $Visited = New-Object System.Collections.Generic.HashSet[string]
    $Parent = @{}

    $Queue.Enqueue($Start)
    $Visited.Add($Start) | Out-Null

    while ($Queue.Count -gt 0) {
        $Node = $Queue.Dequeue()

        if ($Node -eq $Target) {
            $Path = @($Node)
            while ($Parent.ContainsKey($Node)) {
                $Node = $Parent[$Node]
                $Path += $Node
            }
            return $Path[-1..0]
        }

        $Neighbors = $Graph | Where-Object { $_.From -eq $Node } | Select-Object -ExpandProperty To
        foreach ($n in $Neighbors) {
            if (-not $Visited.Contains($n)) {
                $Visited.Add($n) | Out-Null
                $Parent[$n] = $Node
                $Queue.Enqueue($n)
            }
        }
    }

    return $null
}

# ---------------------------------------------------------------------------
# 5. COMPUTE PATHS TO DOMAIN ADMINS
# ---------------------------------------------------------------------------
Write-Host "[+] Computing shortest paths to Domain Admins..."

$DomainAdmins = (Get-ADGroup "Domain Admins").DistinguishedName
$Users = Get-ADUser -Filter * | Select-Object -ExpandProperty DistinguishedName

$Results = foreach ($u in $Users) {
    $Path = Get-ShortestPath -Start $u -Target $DomainAdmins
    if ($Path) {
        [PSCustomObject]@{
            User = $u
            PathLength = $Path.Count
            Path = ($Path -join " -> ")
        }
    }
}

# ---------------------------------------------------------------------------
# 6. RANK USERS BY RISK
# ---------------------------------------------------------------------------
$Ranked = $Results | Sort-Object PathLength

Write-Host "`n=== Most Dangerous Users (Shortest Paths) ==="
$Ranked | Select-Object -First 20 | Format-Table -AutoSize

# ---------------------------------------------------------------------------
# 7. OPTIONAL EXPORT
# ---------------------------------------------------------------------------
if ($ExportCSV) {
    $Ranked | Export-Csv -NoTypeInformation -Path ".\AD_AttackPaths.csv"
}

if ($ExportJSON) {
    $Ranked | ConvertTo-Json | Out-File ".\AD_AttackPaths.json"
}

Write-Host "`n[+] Completed."
