[CmdletBinding()]
Param
( 
    [Parameter(Mandatory=$true, HelpMessage="The Hostname of a Server on which IIS hosts web application - e.g. dev-example.")]
    [String] $hostname,
    [Parameter(Mandatory=$true, HelpMessage="Domain to which belogs the Hostname - e.g. contoso.com.")]
    [String] $domain,
    [Parameter(Mandatory=$false, HelpMessage="(Optional) a prefix which can be use to destinguish generated certificates - e.g. OOO1.")]
    [String] $prefixName,
    [Parameter(Mandatory=$true, HelpMessage="A password which will be used to generate certificates")]
    [String] $password
)

. $PSScriptRoot\Cert-Helpers\Cert-Helpers.ps1

$outDir = "$PSScriptRoot\Out"
$test = Test-Path -Path $outDir
if (!$test) {
    New-Item -ItemType Directory -Path $outDir
} else {
    Get-ChildItem -Path $outDir -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}
}

# Root Cert
$rootCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.root"
if($rootCert) {
   Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $rootCert
}
$rootCert = Read-Certificate -store 'Cert:\LocalMachine\Root' -subject "$hostname.root"
if($rootCert) {
   Remove-Certificate -store 'Cert:\LocalMachine\Root' -certs $rootCert
}

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

$rootCert = Create-Certificate -args $params -path "$outDir\$($prefixName)RootCertificate.crt"


# Intermidate Cert
$interCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.inter"
if($interCert) {
   Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $interCert
}
$interCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.inter"
if($interCert) {
   Remove-Certificate -store 'Cert:\LocalMachine\CA' -certs $interCert
}


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

$interCert = Create-Certificate -args $params -path "$outDir\$($prefixName)IntermediateCertificate.crt"



# Server Cert
$serverCert = Read-Certificate -store 'Cert:\LocalMachine\My' -subject "$hostname.$domain"
if($serverCert) {
   Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $serverCert
}

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

$serverCert = Create-PfxCertificate -args $params -path "$outDir\$($prefixName)ServerCertificate.crt" -pathPfx "$outDir\$($prefixName)ServerCertificate.pfx" -password $password



# Client Cert
$clientCert = Read-Certificate -store 'Cert:\CurrentUser\My' -subject "$hostname.$domain"
if($clientCert) {
   Remove-Certificate -store 'Cert:\CurrentUser\My' -certs $clientCert
}

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

$clientCert = Create-PfxCertificate -args $params -path "$outDir\$($prefixName)ClientCertificate.crt" -pathPfx "$outDir\$($prefixName)ClientCertificate.pfx" -password $password

# Move certs between stores and remove leftovers
Move-Item (Join-Path 'Cert:\LocalMachine\My' $rootCert.Thumbprint) -Destination 'Cert:\LocalMachine\Root' | Out-Null

$cert = Read-Certificate -store 'Cert:\LocalMachine\CA' -subject "$hostname.root"
if($cert) {
   Remove-Certificate -store 'Cert:\LocalMachine\CA' -certs $cert
}

Move-Item (Join-Path 'Cert:\LocalMachine\My' $interCert.Thumbprint) -Destination 'Cert:\LocalMachine\CA' | Out-Null

#Remove-Certificate -store 'Cert:\LocalMachine\My' -certs $interCert