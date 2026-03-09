<#
.SYNOPSIS
    Exports all Key Vault secrets, certificates, and keys across target Azure subscriptions to a CSV file.

.DESCRIPTION
    Connects to Azure and iterates over all Key Vaults in the configured target subscriptions.
    For each vault it collects secrets, certificates, and keys — filtering out any secrets or keys
    that are internally managed by a certificate (i.e. the backing secret/key Azure creates automatically),
    mirroring the behaviour of the Azure Portal.

    Each item is exported as a single row keyed on the normalised vault name, normalised item name, and type.
    A row lists which environments the item was found in, all real vault names, and all real item names —
    each separated by "; " — so items can be compared and tracked across environments in a single view.
    Expiry dates are in UTC.

.PARAMETER TenantId
    The Azure AD tenant ID to authenticate against. Defaults to the VWH tenant.

.PARAMETER TargetSubscriptionNames
    List of subscription display names to include. Defaults to the standard VWH and TOL MANAGEMENT subscriptions.

.PARAMETER ExportPath
    Full path of the output CSV file. Defaults to keyvault_inventory_all_subs.csv in the current user's Documents folder.

.EXAMPLE
    .\Export-KV-Items-To-CSV.ps1

.EXAMPLE
    .\Export-KV-Items-To-CSV.ps1 -TargetSubscriptionNames "SUB A", "SUB P" -ExportPath "C:\temp\kv.csv"
#>
#Requires -Modules Az.Accounts, Az.KeyVault

param(
    [string]   $TenantId                  = "abc-xyz-123-456",
    [string[]] $TargetSubscriptionNames   = @("SUB O", "SUB T", "SUB A", "SUB P"),
    [string]   $ExportPath                = "$HOME\Documents\keyvault_inventory_all_subs.csv"
)

try {
    # Login to Azure
    Connect-AzAccount -AuthScope AzureKeyVaultServiceEndpointResourceId -TenantId $TenantId -ErrorAction Stop
} catch {
    Write-Error "Failed to connect to Azure: $_"
    exit 1
}

# Single source of truth for all sub-environments.
# Display order is defined here; vault/item patterns and the sub-env key map are all derived from this.
$environments = [ordered]@{
    "O"   = @{ VaultPattern = "-o-";    ItemPattern = "-o-"   }
    "O2"  = @{ VaultPattern = "o2-o-";  ItemPattern = "o2-"   }
    "T"   = @{ VaultPattern = "-t-";    ItemPattern = "-t-"   }
    "T2"  = @{ VaultPattern = "t2-t-";  ItemPattern = "t2-"   }
    "A"   = @{ VaultPattern = "-a-";    ItemPattern = "-a-"   }
    "A1" = @{ VaultPattern = "ac1-a-"; ItemPattern = "ac1-"  }
    "P"   = @{ VaultPattern = "-p-";    ItemPattern = "-p-"   }
}

# Derive replacement maps (sorted longest-first so specific patterns match before generic ones)
$replaceVaultNames = [ordered]@{}
$environments.GetEnumerator() | Sort-Object { $_.Value.VaultPattern.Length } -Descending |
    ForEach-Object { $replaceVaultNames[$_.Value.VaultPattern] = "-X-" }

$replaceItemNames = [ordered]@{}
$environments.GetEnumerator() | Sort-Object { $_.Value.ItemPattern.Length } -Descending |
    ForEach-Object {
        $pattern     = $_.Value.ItemPattern
        $replacement = if ($pattern.StartsWith('-')) { "-X-" } else { "X-" }
        $replaceItemNames[$pattern] = $replacement
    }

# Derive sub-env key map for vault name → label lookup (sorted longest-first for matching priority)
$subEnvKeyMap = [ordered]@{}
$environments.GetEnumerator() | Sort-Object { $_.Value.VaultPattern.Length } -Descending |
    ForEach-Object { $subEnvKeyMap[$_.Value.VaultPattern] = $_.Key }

function Get-SubEnvironmentKey {
    param($vaultName)
    foreach ($key in $subEnvKeyMap.Keys) {
        if ($vaultName -match [regex]::Escape($key)) { return $subEnvKeyMap[$key] }
    }
    return $vaultName  # fallback: use vault name as-is if no pattern matches
}


function Get-NormalizedName {
    param($name, $replacements)
    foreach ($key in $replacements.Keys) {
        $name = $name -replace [regex]::Escape($key), $replacements[$key]
    }
    return $name
}

# Get the expiry date of an item, handling different property paths per type
function Get-ItemExpiry {
    param($item, $itemType)
    switch ($itemType) {
        "Certificate" {
            # List items from Get-AzKeyVaultCertificate expose Expires directly
            if ($item.PSObject.Properties["Expires"]) { return $item.Expires }
            # Full certificate objects (fetched by name) expose expiry via the X509 Certificate property
            if ($item.PSObject.Properties["Certificate"] -and $item.Certificate.PSObject.Properties["NotAfter"]) {
                return $item.Certificate.NotAfter
            }
            if ($item.PSObject.Properties["Attributes"] -and $item.Attributes.PSObject.Properties["Expires"]) {
                return $item.Attributes.Expires
            }
        }
        default {
            if ($item.PSObject.Properties["Expires"]) { return $item.Expires }
            if ($item.PSObject.Properties["Attributes"] -and $item.Attributes.PSObject.Properties["Expires"]) {
                return $item.Attributes.Expires
            }
        }
    }
    return $null
}

# Get target subscriptions and warn about any that are missing or disabled
$subscriptions = Get-AzSubscription | Where-Object {
    $_.Name -in $TargetSubscriptionNames -and $_.State -eq "Enabled"
}
$missing = $TargetSubscriptionNames | Where-Object { $_ -notin $subscriptions.Name }
if ($missing) {
    Write-Warning "Subscriptions not found or not enabled: $($missing -join ', ')"
}

$data = [System.Collections.Generic.List[PSCustomObject]]::new()
$itemTypes = @("Secret", "Certificate", "Key")

foreach ($subscription in $subscriptions) {
    try {
        Write-Host "`nProcessing subscription: $($subscription.Name)" -ForegroundColor Cyan
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop

        $vaults = Get-AzKeyVault -ErrorAction Stop
    } catch {
        Write-Warning "Skipping subscription '$($subscription.Name)' due to error: $_"
        continue
    }

    foreach ($vault in $vaults) {
        Write-Host "  Key Vault: $($vault.VaultName)" -ForegroundColor Yellow
        $countBefore = $data.Count

        # Pre-fetch certificates so their names can be used to exclude certificate-backing secrets and keys.
        # This mirrors Azure Portal behaviour: the Secrets and Keys tabs never show items managed by a certificate.
        $certItems = @()
        try {
            $certItems = Get-AzKeyVaultCertificate -VaultName $vault.VaultName -ErrorAction Stop
        } catch {
            Write-Warning "Could not access Certificates in $($vault.VaultName): $_"
        }
        $certNames = @($certItems | Select-Object -ExpandProperty Name)

        foreach ($itemType in $itemTypes) {
            try {
                $items = switch ($itemType) {
                    # Exclude managed flag AND name-matched items: belt-and-suspenders against certificate-backing secrets
                    "Secret"      { Get-AzKeyVaultSecret -VaultName $vault.VaultName -ErrorAction Stop | Where-Object { -not $_.Managed -and $_.Name -notin $certNames } }
                    "Certificate" { $certItems }
                    # Exclude managed flag AND name-matched items: same for certificate-backing keys
                    "Key"         { Get-AzKeyVaultKey    -VaultName $vault.VaultName -ErrorAction Stop | Where-Object { -not $_.Managed -and $_.Name -notin $certNames } }
                }

                foreach ($item in $items) {
                    $expiry = Get-ItemExpiry -item $item -itemType $itemType
                    $expiryFormatted = if ($expiry) { $expiry.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + " UTC" } else { $null }

                    $data.Add([PSCustomObject]@{
                        SubEnvironmentKey   = Get-SubEnvironmentKey -vaultName $vault.VaultName
                        SubscriptionName    = $subscription.Name
                        VaultName           = $vault.VaultName
                        ItemName            = $item.Name
                        ItemType            = $itemType
                        ExpiryDate          = $expiryFormatted
                        NormalizedVaultName = Get-NormalizedName -name $vault.VaultName -replacements $replaceVaultNames
                        NormalizedItemName  = Get-NormalizedName -name $item.Name       -replacements $replaceItemNames
                    })
                }
            } catch {
                Write-Warning "Could not access ${itemType}s in $($vault.VaultName): $_"
            }
        }

        Write-Host "    → $($data.Count - $countBefore) items collected" -ForegroundColor DarkGray
    }
}

# Discover sub-environment keys present in collected data, in the display order defined by $environments.
$allSubEnvKeys  = $environments.Keys | Where-Object { $_ -in $data.SubEnvironmentKey }
# Append any fallback keys (vault names used when no pattern matched) at the end
$allSubEnvKeys += $data.SubEnvironmentKey | Where-Object { $_ -notin $environments.Keys } | Sort-Object -Unique

# Group and pivot: one row per unique normalized item, one column per sub-environment
$exportData = $data |
    Group-Object -Property NormalizedVaultName, NormalizedItemName, ItemType |
    ForEach-Object {
        $group = $_.Group
        $first = $group[0]

        $row = [ordered]@{
            NormalizedVaultName = $first.NormalizedVaultName
            NormalizedItemName  = $first.NormalizedItemName
            ItemType            = $first.ItemType
        }

        foreach ($subEnv in $allSubEnvKeys) {
            $match = $group | Where-Object { $_.SubEnvironmentKey -eq $subEnv } | Select-Object -First 1
            $row[$subEnv] = if (-not $match)         { "n/a" }
                             elseif ($match.ExpiryDate) { $match.ExpiryDate }
                             else                       { "" }
        }

        [PSCustomObject]$row
    } |
    Sort-Object NormalizedVaultName, NormalizedItemName

# Export data to CSV if we found anything
if ($exportData.Count -gt 0) {
    try {
        $exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nExport completed: $ExportPath ($($exportData.Count) normalized items from $($data.Count) raw entries)" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export data to CSV: $_"
    }
} else {
    Write-Warning "`nNo secrets, certificates or keys found to export."
}
