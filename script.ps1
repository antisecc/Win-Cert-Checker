function Search-VulnerableCertificates {
    [CmdletBinding()]
    param (
        [string]$CertStoreLocation = 'Cert:\LocalMachine\My'
    )

    begin {
        $criticalCertificateStorePaths = @(
            'Cert:\LocalMachine\Root',
            'Cert:\LocalMachine\AuthRoot',
            'Cert:\LocalMachine\CA',
            'Cert:\LocalMachine\Trust'
        )
    }

    process {
        try {
            $allCertificates = Get-ChildItem -Path $CertStoreLocation -Recurse
            $vulnerableCertificates = @()

            foreach ($certificate in $allCertificates) {
                if ($certificate.HasPrivateKey) {
                    $certificatePrivateKey = $certificate.PrivateKey

                    if ($certificatePrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                        $rsaKeySize = $certificatePrivateKey.KeySize

                        if ($rsaKeySize -lt 2048) {
                            # Check for certificate expiration
                            $expirationDate = $certificate.NotAfter
                            $currentDate = Get-Date

                            if ($expirationDate -lt $currentDate) {
                                # Check for invalid certificate chain
                                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                                $chain.Build($certificate)

                                if ($chain.ChainStatus.Length -eq 0) {
                                    # Check for lack of key usage constraints or weak key usage constraints
                                    $keyUsage = $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }

                                    if ($keyUsage) {
                                        $keyUsageFlags = $keyUsage.Format($true) -replace "[^\d]", ""
                                        $weakKeyUsage = ($keyUsageFlags -notmatch "KeyEncipherment") -or ($keyUsageFlags -notmatch "DataEncipherment")

                                        if ($weakKeyUsage) {
                                            $vulnerableCertificates += $certificate
                                        }
                                    } else {
                                        # Lack of key usage constraints
                                        $vulnerableCertificates += $certificate
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ($vulnerableCertificates.Count -gt 0) {
                Write-Output "Found $($vulnerableCertificates.Count) vulnerable certificate(s):"

                foreach ($certificate in $vulnerableCertificates) {
                    Write-Output "Subject: $($certificate.Subject)"
                    Write-Output "Issuer: $($certificate.Issuer)"
                    Write-Output "Thumbprint: $($certificate.Thumbprint)"
                    Write-Output "NotBefore: $($certificate.NotBefore)"
                    Write-Output "NotAfter: $($certificate.NotAfter)"
                    Write-Output "HasPrivateKey: $($certificate.HasPrivateKey)"
                    Write-Output "Expired: $($certificate.NotAfter -lt (Get-Date))"
                    Write-Output "InvalidChain: $($chain.ChainStatus -eq $null)"
                    Write-Output "WeakKeyUsage: $($weakKeyUsage)"
                    Write-Output "--------------------------------------------"
                }
            } else {
                Write-Output "No vulnerable certificates found."
            }
        } catch {
            Write-Error $_.Exception.Message
        }
    }

    end {
    }
}

# Search for vulnerable certificates
Search-VulnerableCertificates
