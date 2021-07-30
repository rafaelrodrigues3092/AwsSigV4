import datetime, hashlib, hmac

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def getRequestHeaders(
        https_endpoint: str,
        access_key: str,
        secret_key: str,
        method: str = 'POST',
        token: str = None,
        request_parameters: dict = None,
        query_string: str = None,
    ):

    # validate method to be POST or GET
    if method not in ['POST', 'GET']:
        raise ValueError('method must be POST or GET')

    if method == 'POST':
        if request_parameters is None:
            raise ValueError('request_parameters is required when using the POST method')
        canonical_querystring = ''
        payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

    else:
        if query_string is None:
            raise ValueError('query_strings is required when using the POST method')
        canonical_querystring = query_string
        payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

    method = method.upper()
    service = 'execute-api'
    endpoint_splt = https_endpoint.split('/')
    host = endpoint_splt[2]
    canonical_uri = '/'+('/'.join(endpoint_splt[3:]))
    region = host.split('.')[2]

    # Create a date for headers and the credential string
    content_type = 'application/x-amz-json-1.0'
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope


    canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n'
    signed_headers = 'content-type;host;x-amz-date'
    if token:
        signed_headers = signed_headers+';x-amz-security-token'
        canonical_headers =canonical_headers + 'x-amz-security-token:' + token + '\n'


    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    signing_key = getSignatureKey(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
    headers = {
            'Content-Type':content_type,
            'X-Amz-Date':amz_date,
            'Authorization':authorization_header
        }
    if token:
        headers['x-amz-security-token'] = token

    return headers