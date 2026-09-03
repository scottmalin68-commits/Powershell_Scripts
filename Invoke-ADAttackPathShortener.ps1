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
Scott Malin, CISSP

LAST MODIFIED
--------------
2026‑09‑03

CHANGELOG
----------
v1.1.0
• Performance optimization: Converted edge lookup to a Hash Table adjacency list to eliminate pipeline filtering inside BFS.
• Identity normalization: Resolved SID/IdentityReference mismatches by mapping ACE identities to DNs.
• Scoped ACL queries: Restricted LDAP query target objects to prevent memory exhaustion on large directory stores.
• Replaced array concatenation in path backtracking with List[string] collection for clean path ordering.

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

# Helper map to translate SIDs / IdentityReferences to DistinguishedNames
$IdentityMap = @{}

Write-Host "[+] Resolving identity mappings..."
Get-ADObject -Filter * | ForEach-Object {
    if ($_.SID) { $IdentityMap[$_.SID.Value] = $_.DistinguishedName }
    if ($_.Name) { $IdentityMap[$_.Name] = $_.DistinguishedName }
    $IdentityMap[$_.DistinguishedName] = $_.DistinguishedName
}

# ---------------------------------------------------------------------------
# 1. COLLECT GROUP MEMBERSHIP DATA
# ---------------------------------------------------------------------------
Write-Host "[+] Collecting group memberships..."
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
Write-Host "[+] Collecting ACL rights on core AD targets..."

# Filter query to key structural objects (users, groups, computers, domain root) to optimize memory usage
$TargetObjects = Get-ADObject -LDAPFilter "(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=domainDNS))" -Properties ntSecurityDescriptor

$ACLs = foreach ($obj in $TargetObjects) {
    $sd = $obj.ntSecurityDescriptor
    if ($sd) {
        foreach ($ace in $sd.Access) {
            if ($ace.ActiveDirectoryRights -match "WriteOwner|GenericAll|WriteDacl|ExtendedRight") {
                $rawIdentity = $ace.IdentityReference.Value
                
                # Resolve identity to DN if map exists, else retain raw string
                $fromDN = if ($IdentityMap.ContainsKey($rawIdentity)) { $IdentityMap[$rawIdentity] } else { $rawIdentity }

                [PSCustomObject]@{
                    From = $fromDN
                    To   = $obj.DistinguishedName
                    Type = "ACLControl"
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 3. BUILD GRAPH & ADJACENCY LOOKUP
# ---------------------------------------------------------------------------
$Graph = $GroupEdges + $ACLs
Write-Host "[+] Graph built. Total edges:" $Graph.Count

Write-Host "[+] Indexing graph adjacency list for fast BFS traversal..."
$AdjacencyList = @{}
foreach ($edge in $Graph) {
    if (-not $AdjacencyList.ContainsKey($edge.From)) {
        $AdjacencyList[$edge.From] = [System.Collections.Generic.List[string]]::new()
    }
    $AdjacencyList[$edge.From].Add($edge.To)
}

# ---------------------------------------------------------------------------
# 4. SHORTEST PATH ENGINE
# ---------------------------------------------------------------------------
function Get-ShortestPath {
    param(
        [string]$Start,
        [string]$Target
    )

    $Queue = [System.Collections.Queue]::new()
    $Visited = [System.Collections.Generic.HashSet[string]]::new()
    $Parent = @{}

    $Queue.Enqueue($Start)
    $Visited.Add($Start) | Out-Null

    while ($Queue.Count -gt 0) {
        $Node = $Queue.Dequeue()

        if ($Node -eq $Target) {
            $Path = [System.Collections.Generic.List[string]]::new()
            $Path.Add($Node)
            while ($Parent.ContainsKey($Node)) {
                $Node = $Parent[$Node]
                $Path.Add($Node)
            }
            $Path.Reverse()
            return $Path
        }

        if ($AdjacencyList.ContainsKey($Node)) {
            foreach ($n in $AdjacencyList[$Node]) {
                if (-not $Visited.Contains($n)) {
                    $Visited.Add($n) | Out-Null
                    $Parent[$n] = $Node
                    $Queue.Enqueue($n)
                }
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
            User       = $u
            PathLength = $Path.Count
            Path       = ($Path -join " -> ")
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