try {
    # Login to Azure
    Connect-AzAccount -ErrorAction Stop
} catch {
    Write-Error "Failed to connect to Azure: $_"
    exit 1
}

# Define target subscriptions
$targetNames = @("YOUR-SUBSCRIPTION-NAME", "ANOTHER-SUBSCRIPTION-NAME")

# Get target subscriptions

$subscriptions = Get-AzSubscription | Where-Object {
    $_.Name -in $targetNames -and $_.State -eq "Enabled"
}
$data = @()

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
        Write-Host "Key Vault: $($vault.VaultName)" -ForegroundColor Yellow

        # Get secrets
        try {
            $secrets = Get-AzKeyVaultSecret -VaultName $vault.VaultName -ErrorAction Stop
            foreach ($secret in $secrets) {
                # Try to get expiry date from multiple possible properties
                $expiry = $null
                if ($secret.PSObject.Properties["Expires"]) {
                    $expiry = $secret.Expires
                } elseif ($secret.PSObject.Properties["Attributes"] -and $secret.Attributes.PSObject.Properties["Expires"]) {
                    $expiry = $secret.Attributes.Expires
                }
                $expiryFormatted = $null
                if ($expiry) {
                    $expiryFormatted = $expiry.ToLocalTime().ToString('dd-MM-yyyy HH:mm:ss')
                }
                $data += [PSCustomObject]@{
                    SubscriptionName = $subscription.Name
                    VaultName        = $vault.VaultName
                    ItemName         = $secret.Name
                    ItemType         = "Secret"
                    ExpiryDate       = $expiryFormatted
                    Enabled          = $secret.Attributes.Enabled
                }
            }
        } catch {
            Write-Warning "Could not access secrets in $($vault.VaultName): $_"
        }

        # Get certificates
        try {
            $certs = Get-AzKeyVaultCertificate -VaultName $vault.VaultName -ErrorAction Stop
            foreach ($cert in $certs) {
                # Try to get expiry date from multiple possible properties
                $expiry = $null
                if ($cert.PSObject.Properties["Certificate"] -and $cert.Certificate.PSObject.Properties["NotAfter"]) {
                    $expiry = $cert.Certificate.NotAfter
                } elseif ($cert.PSObject.Properties["Attributes"] -and $cert.Attributes.PSObject.Properties["Expires"]) {
                    $expiry = $cert.Attributes.Expires
                }
                $expiryFormatted = $null
                if ($expiry) {
                    $expiryFormatted = $expiry.ToLocalTime().ToString('dd-MM-yyyy HH:mm:ss')
                }
                $data += [PSCustomObject]@{
                    SubscriptionName = $subscription.Name
                    VaultName        = $vault.VaultName
                    ItemName         = $cert.Name
                    ItemType         = "Certificate"
                    ExpiryDate       = $expiryFormatted
                    Enabled          = $cert.Attributes.Enabled
                }
            }
        } catch {
            Write-Warning "Could not access certificates in $($vault.VaultName): $_"
        }

        # Get keys
        try {
            $keys = Get-AzKeyVaultKey -VaultName $vault.VaultName -ErrorAction Stop
            foreach ($key in $keys) {
                # Try to get expiry date from multiple possible properties
                $expiry = $null
                if ($key.PSObject.Properties["Expires"]) {
                    $expiry = $key.Expires
                } elseif ($key.PSObject.Properties["Attributes"] -and $key.Attributes.PSObject.Properties["Expires"]) {
                    $expiry = $key.Attributes.Expires
                }
                $expiryFormatted = $null
                if ($expiry) {
                    $expiryFormatted = $expiry.ToLocalTime().ToString('dd-MM-yyyy HH:mm:ss')
                }
                $data += [PSCustomObject]@{
                    SubscriptionName = $subscription.Name
                    VaultName        = $vault.VaultName
                    ItemName         = $key.Name
                    ItemType         = "Key"
                    ExpiryDate       = $expiryFormatted
                    Enabled          = $key.Attributes.Enabled
                }
            }
        } catch {
            Write-Warning "Could not access keys in $($vault.VaultName): $_"
        }
    }
}

# Export to CSV if we found anything
if ($data.Count -gt 0) {
    try {
        $exportPath = "$HOME\Documents\keyvault_inventory_all_subs.csv"
        $data | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nExport completed: $exportPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export data to CSV: $_"
    }
} else {
    Write-Warning "`nNo secrets, certificates or keys found to export."
}
