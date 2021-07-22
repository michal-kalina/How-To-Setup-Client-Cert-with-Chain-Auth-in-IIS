[CmdletBinding()]
Param
( 
    [Parameter(Mandatory=$true)]
    [String] $hostname, #dev-example
    [Parameter(Mandatory=$true)]
    [String] $domain, #contoso.com
    [Parameter(Mandatory=$false)]
    [String] $profixNmae # ####-
    [Parameter(Mandatory=$true)]
    [String] $password
)

Import-Module Cert-Helpers -Function Read-Certificate, Remove-Certificate, Create-Certificate, Create-PfxCertificate

$outDir = "$PSScriptRoot\Out"
$test = Test-Path -Path $outDir
if (!$test) {
    New-Item -ItemType Directory -Path $outDir
} else {
    Get-ChildItem -Path $outDir -Include *.* -File -Recurse | foreach { $_.Delete()}
}

# Root Cert
$rootCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.root"
Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $rootCert
$rootCert = Read-Certificate -store 'Cert:\LocalMachine\Root' -subject "$hostname.root"
Remove-Certificate -store 'Cert:\LocalMachine\Root' -certs $rootCert

$params = @{
   Subject = "$hostname.root"
   #DnsName = "$hostname.root"
   KeyLength = 2048
   KeyAlgorithm = 'RSA'
   HashAlgorithm = 'SHA512'
   KeyExportPolicy = 'Exportable'
   NotAfter = ((Get-Date -Date "12/31/2039 18:59:59"))
   CertStoreLocation = 'Cert:\LocalMachine\My'
   KeyUsage = 'CertSign','CRLSign', 'DigitalSignature'
   #Extension = $null
   FriendlyName = "$hostname.root"
   KeySpec = 'Signature'
   Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider"
   Type = 'Custom'
   TextExtension = @(
        "2.5.29.19={text}cA=true&pathLength=2"
   )
}

$rootCert = Create-Certificate -args $params -path "$outDir\$profixNmaeRootCertificate.crt"


# Intermidate Cert
$interCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.inter"
Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $interCert
$interCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.inter"
Remove-Certificate -store 'Cert:\LocalMachine\CA' -certs $interCert


$params = @{
   Subject = "$hostname.inter"
   #DnsName = "$hostname.inter"
   Signer = $rootCert
   KeyLength = 2048
   KeyAlgorithm = 'RSA'
   HashAlgorithm = 'SHA512'
   KeyExportPolicy = 'Exportable'
   NotAfter = ((Get-Date -Date "12/31/2039 18:59:59"))
   CertStoreLocation = 'Cert:\LocalMachine\My'
   KeyUsage = 'CertSign','CRLSign', 'DigitalSignature'
   #Extension = null
   FriendlyName = "$hostname.inter"
   KeySpec = 'Signature'
   Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider"
   Type = 'Custom'
   TextExtension = @(
        "2.5.29.19={text}cA=true&pathLength=1"
   )
}

$interCert = Create-Certificate -args $params -path "$outDir\$profixNmaeIntermediateCertificate.crt"



# Server Cert
$serverCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.$domain"
Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $serverCert

$params = @{
   Subject = "CN=$hostname, CN=*.$domain, CN=$hostname.$domain"
   DnsName = "$hostname.$domain"
   Signer = $interCert
   KeyLength = 2048
   KeyAlgorithm = 'RSA'
   HashAlgorithm = 'SHA512'
   KeyExportPolicy = 'Exportable'
   NotAfter = ((Get-Date -Date "12/31/2039 18:59:59"))
   CertStoreLocation = 'Cert:\LocalMachine\My'
   KeyUsage = 'CertSign','CRLSign', 'DigitalSignature'
   #Extension = $null
   FriendlyName = "$hostname.$domain"
   KeySpec = 'KeyExchange'
   Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider"
   Type = 'SSLServerAuthentication'
   TextExtension = @(
        "2.5.29.37={text}1.3.6.1.5.5.7.3.1"
   )
}

$serverCert = Create-PfxCertificate -args $params -path "$outDir\$profixNmaeServerCertificate.crt" -pathPfx "$outDir\$profixNmaeServerCertificate.pfx" -password $password



# Client Cert
$clientCert = Read-Certificate -store 'Cert:\CurrentUser\My' -subject "$hostname.$domain"
Remove-Certificate -store 'Cert:\CurrentUser\My' -certs $clientCert

$params = @{
   Subject = "CN=$hostname, CN=*.$domain, CN=$hostname.$domain"
   DnsName = "$hostname.$domain"
   Signer = $interCert
   KeyLength = 2048
   KeyAlgorithm = 'RSA'
   HashAlgorithm = 'SHA512'
   KeyExportPolicy = 'Exportable'
   NotAfter = ((Get-Date -Date "12/31/2039 18:59:59"))
   CertStoreLocation = 'Cert:\CurrentUser\My'
   KeyUsage = 'CertSign','CRLSign', 'DigitalSignature'
   #Extension = $null
   FriendlyName = "$hostname.$domain"
   KeySpec = 'KeyExchange'
   Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider"
   Type = 'SSLServerAuthentication'
   TextExtension = @(
        "2.5.29.37={text}1.3.6.1.5.5.7.3.2"
   )
}

$clientCert = Create-PfxCertificate -args $params -path "$outDir\$profixNmaeClientCertificate.crt" -pathPfx "$outDir\$profixNmaeClientCertificate.pfx" -password $password

# Move certs between stores and remove leftovers
Move-Item (Join-Path 'Cert:\LocalMachine\My' $rootCert.Thumbprint) -Destination 'Cert:\LocalMachine\Root' | Out-Null

$cert = Read-Certificate -store 'Cert:\LocalMachine\CA' -subject "$hostname.root"
Remove-Certificate -store 'Cert:\LocalMachine\CA' -certs $cert

Move-Item (Join-Path 'Cert:\LocalMachine\My' $interCert.Thumbprint) -Destination 'Cert:\LocalMachine\CA' | Out-Null

#Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $interCert


#& certutil.exe -encode "$outDir\CUST-75491-ClientCertificate.crt" "$outDir\CUST-75491-ClientCertificate_base64.crt"

Get-Website -Name "wpm-test-page"

#Run cmd as admin
#netsh http show sslcert
#netsh http delete sslcert hostnameport=dev-kra-mkal-03.aad2.lab:443
#netsh http add sslcert hostnameport=dev-kra-mkal-03.aad2.lab:443 certhash=a32a516e5c999ce07f0f2e9a3fb5bcd247857f8b appid={4dc3e181-e14b-4a21-b022-59fc669b0914} certstorename=MY verifyclientcertrevocation=enable VerifyRevocationWithCachedClientCertOnly=disable UsageCheck=enable clientcertnegotiation=enable