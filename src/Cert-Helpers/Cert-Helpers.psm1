
function Read-Certificate {
    param(
        [Parameter(Mandatory=$true)]
        [System.String] $store, 
        [Parameter(Mandatory=$true)]
        [System.String] $subject
    )
    $certs = Get-ChildItem $store -Recurse | where { 
        $_.Subject -like "*$subject*"
    }
    return $certs
}

function Remove-Certificate {
    param(
        [Parameter(Mandatory=$true)]
        [System.String] $store, 
        [Parameter(Mandatory=$true)]
        $certs
    )
    $certs | % {
        $thumbprint = $_.Thumbprint
        $p = $store + "\$thumbprint"
        
        try {
            (Get-ChildItem $p) | Remove-Item
        }
        catch {}
    }
}

function Create-Certificate() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable] $args,
        [Parameter(Mandatory=$true)]
        [System.String] $path
    )
    $selfSignedCert = New-SelfSignedCertificate @args

    Export-Certificate -Cert $selfSignedCert -FilePath $path | Out-Null

    return $selfSignedCert
}

function Create-PfxCertificate() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable] $args,
        [Parameter(Mandatory=$true)]
        [System.String] $path,
        [Parameter(Mandatory=$true)]
        [System.String] $pathPfx,
        [Parameter(Mandatory=$true)]
        [System.String] $password
    )
    $selfSignedCert = New-SelfSignedCertificate @args
    Export-Certificate -Cert $selfSignedCert -FilePath $path | Out-Null

    $passwordSecStr = ConvertTo-SecureString -String $password -Force -AsPlainText
    Export-PfxCertificate -Cert $selfSignedCert -FilePath $pathPfx -Password $passwordSecStr | Out-Null

    return $selfSignedCert
}

Export-ModuleMember -Function  Read-Certificate, Remove-Certificate, Create-Certificate, Create-PfxCertificate