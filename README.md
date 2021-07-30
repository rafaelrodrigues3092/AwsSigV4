# AwsSigV4

## Signing AWS API Gateway requests with AWS Signature Version 4

### Abstract

There is a lack of documentation on how to properly perform an signed AWS API Gateway request.
Online, there's an abundance of examples on how to perform this task for services like S3, DynamoDB, and EC2, but little to none on how to perform it for a user-created API Gateway endpoint.

Request signing is required when the API Gateway methods are using AWS_IAM Authorization. See: <https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html>

### Using Python

Please see the [Python Example](python)

### Using PowerShell

Please see the [PowerShell Example](PowerShell)
