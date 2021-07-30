function Sign-HmacSHA256
{
    param
    (
        [Parameter(Mandatory=$true)][byte[]]$Key,
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)][switch]$bitConverted
    )

    $kha = [System.Security.Cryptography.HashAlgorithm]::Create('HMACSHA256')
    $kha.Key = $Key
    $hash =  $kha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Message))
    if($bitConverted.IsPresent)
    {
        $hashString = [System.BitConverter]::ToString($hash)
        return $hashString.Replace('-', '').ToLower()
    }
    else
    {
        return $hash
    }

}


function Get-SignatureKey
{
    param
    (
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$DateStamp,
        [Parameter(Mandatory=$true)][string]$RegionName,
        [Parameter(Mandatory=$true)][string]$ServiceName
    )
    $kSecret = [Text.Encoding]::UTF8.GetBytes(("AWS4" + $Key).toCharArray())
    $kDate = Sign-HmacSHA256 -Key $kSecret -Message $DateStamp ;
    $kRegion = Sign-HmacSHA256 -Key $kDate -Message $RegionName  ;
    $kService = Sign-HmacSHA256 -Key $kRegion -Message $ServiceName  ;
    $kSigning = Sign-HmacSHA256 -Key $kService -Message "aws4_request"  ;
    return $kSigning
}

function Get-Hash
{
    param
    (
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Request
    )

    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('SHA256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Request))
    $hashString = [System.BitConverter]::ToString($hash)
    return $hashString.Replace('-', '').ToLower()

}

Function Get-AWS4SignatureHeaders
{
    param
    (
        [Parameter(Mandatory=$true)][string]$HTTPEndpoint,
        [Parameter(Mandatory=$true)][string]$RequestParameters,
        [Parameter(Mandatory=$true)][string]$AwsAccessKey,
        [Parameter(Mandatory=$true)][string]$AWSSecretKey,
        [Parameter(Mandatory=$true)][ValidateSet("GET", "POST")][string]$Method,
        [Parameter(Mandatory=$false)][string]$AwsToken = $null
    )

    # validate $Method to be GET or POST
    if ($Method -ne 'GET' -and $Method -ne 'POST')
    {
        throw "$Method must be GET or POST"
    }

    if($Method -eq 'GET')
    {
        $canonical_querystring = $RequestParameters
        $payload_hash =  Get-Hash -Request ''
    }
    else
    {
        $canonical_querystring = ''
        $payload_hash =  Get-Hash -Request $RequestParameters
    }

    $service = 'execute-api'
    $endpoint_splt = $HTTPEndpoint.split('/')
    $host1 = $endpoint_splt[2]
    $region = $host1.split('.')[2]
    $canonical_uri = '/'+[String]::Join('/',($endpoint_splt[3..$($endpoint_splt.length)]))

    $content_type = 'application/x-amz-json-1.0'
    $amz_date = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $date_stamp = [DateTime]::UtcNow.ToString('yyyyMMdd')


    $canonical_headers = 'content-type:' + $content_type + "`n" + 'host:' + $host1 + "`n" + 'x-amz-date:' + $amz_date + "`n"
    $signed_headers = 'content-type;host;x-amz-date'
    if ($null -ne $AwsToken)
    {
        $signed_headers = $signed_headers+';x-amz-security-token'
        $canonical_headers = $canonical_headers + 'x-amz-security-token:' + $AwsToken + "`n"
    }

    $canonical_request = $Method + "`n" +$canonical_uri + "`n" + $canonical_querystring + "`n" + $canonical_headers + "`n" + $signed_headers + "`n" + $payload_hash

    $algorithm = 'AWS4-HMAC-SHA256'
    $credential_scope = $date_stamp + '/' + $region + '/' + $service + '/' + 'aws4_request'
    $string_to_sign = $algorithm + "`n" +  $amz_date + "`n" +  $credential_scope + "`n" +  (Get-Hash -Request $canonical_request )


    $signing_key = Get-SignatureKey -Key $AWSSecretKey -DateStamp $date_stamp -RegionName $region -ServiceName $service

    $signature =  Sign-HmacSHA256 -Key $signing_key -Message $string_to_sign -bitConverted

    $authorization_header = $algorithm + ' ' + 'Credential=' + $AwsAccessKey + '/' + $credential_scope + ', ' +  'SignedHeaders=' + $signed_headers + ', ' + 'Signature=' + $signature
    $headers = @{
        'Content-Type'=$content_type
        'X-Amz-Date'=$amz_date
        'Authorization'=$authorization_header
    }
    if ($null -ne $AwsToken)
    {
        $headers['x-amz-security-token'] = $AwsToken
    }

    return $headers
}

Export-ModuleMember -Function Get-AWS4SignatureHeaders