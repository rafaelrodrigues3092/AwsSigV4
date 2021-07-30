Import-Module "$PSScriptRoot\AwsSigV4.psm1" -DisableNameChecking
Import-Module AWSPowerShell -DisableNameChecking

$ErrorActionPreference = "Stop"
#API Gateway endpoint
$BaseUri = 'https://azazazazaz.execute-api.us-east-1.amazonaws.com/petstore/pets'

#Get AWS Temporary credentials
#Use a profile name as needed
$Credentials = (Get-AWSCredential -ErrorAction Stop).GetCredentials()

#GET Request
#QueryString must be alphabetically ordered
$QueryString = "bar=foo&foo=bar"

$Headers = Get-AWS4SignatureHeaders `
            -HTTPEndpoint $BaseUri `
            -RequestParameters $QueryString `
            -Method 'GET' `
            -AwsAccessKey $Credentials.AccessKey `
            -AWSSecretKey $Credentials.SecretKey `
            -AwsToken $Credentials.Token


#The api includes the ? query string paramaters
$ApiEndpoint = "$($BaseUri)?$($QueryString)"
Invoke-RestMethod -Method 'GET' -Uri $ApiEndpoint -Headers $Headers


#POST Request
$Body = @{
    "foo" = "bar"
}

$Payload = $Body | ConvertTo-Json

$Headers = Get-AWS4SignatureHeaders `
            -HTTPEndpoint $BaseUri `
            -RequestParameters $Payload `
            -Method 'POST' `
            -AwsAccessKey $Credentials.AccessKey `
            -AWSSecretKey $Credentials.SecretKey `
            -AwsToken $Credentials.Token

Invoke-RestMethod -Method 'POST' -Uri $BaseUri -Headers $Headers -Body $Payload
