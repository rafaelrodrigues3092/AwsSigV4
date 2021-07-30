import boto3
import requests
import json
import AwsSigV4 as AwsSigV4

#API Gateway endpoint

url = "https://e8hza3dcpk.execute-api.us-east-1.amazonaws.com/latest/status"

#Get AWS Temporary credentials
#Use a profile name as needed
aws_session = boto3.session.Session()
credentials = aws_session.get_credentials()
ACCESS_KEY = credentials.access_key
SECRET_KEY = credentials.secret_key
SESSION_TOKEN = credentials.token


#GET request

#the query strings must be alphabetically ordered
query_string = "bar=foo&foo=bar"

get_headers = AwsSigV4.getRequestHeaders(
    https_endpoint = url,
    method='GET',
    query_string = query_string,
    access_key = ACCESS_KEY,
    secret_key = SECRET_KEY,
    token = SESSION_TOKEN
)
api_endpoint = f'{url}?{query_string}'
r = requests.get(api_endpoint, headers=get_headers)


print(str(r.status_code))
print(r.reason)
print(r.text)


#POST request
body = {
    'foo':'bar'
}

request_params = json.dumps(body)

post_headers = AwsSigV4.getRequestHeaders(
    https_endpoint = url,
    method='POST',
    request_parameters = request_params,
    access_key = ACCESS_KEY,
    secret_key = SECRET_KEY,
    token = SESSION_TOKEN
)
r = requests.post(url, data=request_params, headers=post_headers)

print(str(r.status_code))
print(r.reason)
print(r.text)
