# Certificate Vulnerability Checker
Overview
The Certificate Vulnerability Checker is a basic PowerShell script designed to identify potential vulnerabilities in X.509 certificates on a Windows machine. It focuses on four key criteria:

Key Size: Checks for certificates with a key size less than 2048 bits.
Expiration Date: Identifies certificates that have expired.
Certificate Chain: Verifies the validity of the certificate chain.
Key Usage Constraints: Detects certificates with a lack of key usage constraints or weak key usage constraints.
This script is not intended for advanced analysis and testing; rather, it serves as a starting point for basic security assessments related to certificates.

# Disclaimer
This script provides a basic overview of potential certificate vulnerabilities and is not a comprehensive security assessment tool. It is recommended to perform thorough security analyses using specialized tools for in-depth assessments.

# Usage
Clone the repository or download the script.
Open a PowerShell console.
Navigate to the directory containing the script.

Run the script: 
``` .\Search-VulnerableCertificates.ps1 ```

The script supports an optional parameter for specifying a custom certificate store location. By default, it searches in 'Cert:\LocalMachine\My' and critical certificate store paths.

``` .\Search-VulnerableCertificates.ps1 -CertStoreLocation 'Cert:\LocalMachine\My' ``` 

# Disclaimer
This script provides a basic overview of potential certificate vulnerabilities and is not a comprehensive security assessment tool. It is recommended to perform thorough security analyses using specialized tools for in-depth assessments.