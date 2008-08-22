'''
Example consumer.
'''
import httplib
import time
import oauth

SERVER = 'pureshape.corp.yahoo.com'
PORT = 8080

REQUEST_TOKEN_URL = 'http://pureshape.corp.yahoo.com/request_token'
ACCESS_TOKEN_URL = 'http://pureshape.corp.yahoo.com/access_token'
RENEW_ACCESS_TOKEN_URL = 'http://pureshape.corp.yahoo.com/renew_access_token'
AUTHORIZATION_URL = 'http://pureshape.corp.yahoo.com/authorize'
RESOURCE_URL = 'http://pureshape.corp.yahoo.com/photos'
CALLBACK_URL = 'http://printer.example.com/request_token_ready'

# key and secret granted by the service provider for this consumer application - same as the MockOAuthDataStore
CONSUMER_KEY = 'key'
CONSUMER_SECRET = 'secret'

# example client using httplib with headers
class SimpleOAuthClient(oauth.OAuthClient):

    def __init__(self, server, port=httplib.HTTP_PORT, request_token_url='', access_token_url='', authorization_url='', renew_token_url=''):
        self.server = server
        self.port = port
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.renew_token_url = renew_token_url
        self.authorization_url = authorization_url
        self.connection = httplib.HTTPConnection("%s:%d" % (self.server, self.port))

    def fetch_request_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        self.connection.request(oauth_request.http_method, self.request_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        return oauth.OAuthToken.from_string(response.read())

    def fetch_access_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        self.connection.request(oauth_request.http_method, self.access_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        return oauth.OAuthToken.from_string(response.read())
    
    def renew_access_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        self.connection.request(oauth_request.http_method, self.renew_token_url, headers=oauth_request.to_header())
        response = self.connection.getresponse()
        return oauth.OAuthToken.from_string(response.read())

    def authorize_token(self, oauth_request):
        # via url
        # -> typically just some okay response
        self.connection.request(oauth_request.http_method, oauth_request.to_url()) 
        response = self.connection.getresponse()
        return response.read()

    def access_resource(self, oauth_request):
        # via post body
        # -> some protected resources
        headers = {'Content-Type' :'application/x-www-form-urlencoded'}
        self.connection.request('POST', RESOURCE_URL, body=oauth_request.to_postdata(), headers=headers)
        response = self.connection.getresponse()
        return response.read()

def run_example():

    # setup
    print '** OAuth Python Library Example **'
    client = SimpleOAuthClient(SERVER, PORT, REQUEST_TOKEN_URL, ACCESS_TOKEN_URL, AUTHORIZATION_URL, RENEW_ACCESS_TOKEN_URL)
    consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
    signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
    signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()
    pause()

    # get request token
    print '* Obtain a request token ...'
    pause()
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, http_url=client.request_token_url)
    oauth_request.sign_request(signature_method_plaintext, consumer, None)
    print 'REQUEST (via headers)'
    print 'parameters: %s' % str(oauth_request.parameters)
    pause()
    token = client.fetch_request_token(oauth_request)
    print 'GOT'
    print 'key: %s' % str(token.key)
    print 'secret: %s' % str(token.secret)
    if token.expires:
        print 'expiration: %s' % str(token.expires)
    pause()

    print '* Authorize the request token ...'
    pause()
    oauth_request = oauth.OAuthRequest.from_token_and_callback(token=token, callback=CALLBACK_URL, http_url=client.authorization_url)
    print 'REQUEST (via url query string)'
    print 'parameters: %s' % str(oauth_request.parameters)
    pause()
    # this will actually occur only on some callback
    response = client.authorize_token(oauth_request)
    print 'GOT'
    print response
    pause()

    # get access token
    print '* Obtain an access token ...'
    pause()
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, http_url=client.access_token_url)
    oauth_request.sign_request(signature_method_plaintext, consumer, token)
    print 'REQUEST (via headers)'
    print 'parameters: %s' % str(oauth_request.parameters)
    pause()
    token = client.fetch_access_token(oauth_request)
    print 'GOT'
    print 'key: %s' % str(token.key)
    print 'secret: %s' % str(token.secret)
    if token.expires:
        print 'expiration: %s' % str(token.expires)
    if token.session_handle:
        print 'session handle: %s' % str(token.session_handle)
    if token.session_expires:
        print 'session expiration: %s' % str(token.session_expires)
    pause()

    # access some protected resources
    print '* Access protected resources ...'
    pause()
    parameters = {'file': 'vacation.jpg', 'size': 'original', 'oauth_callback': CALLBACK_URL} # resource specific params
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, http_method='POST', http_url=RESOURCE_URL, parameters=parameters)
    oauth_request.sign_request(signature_method_hmac_sha1, consumer, token)
    print 'REQUEST (via post body)'
    print 'parameters: %s' % str(oauth_request.parameters)
    pause()
    params = client.access_resource(oauth_request)
    print 'GOT'
    print 'non-oauth parameters: %s' % params
    pause()
    
    # renew access token (new in 2008.1)
    print '* Renew the access token ...'
    pause()
    if token.expires:
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, http_url=client.renew_token_url)
        oauth_request.sign_request(signature_method_plaintext, consumer, token)
        print 'REQUEST (via headers)'
        print 'parameters: %s' % str(oauth_request.parameters)
        pause()
        token = client.renew_access_token(oauth_request)
        print 'GOT'
        print 'key: %s' % str(token.key)
        print 'secret: %s' % str(token.secret)
        print 'expiration: %s' % str(token.expires)
        print 'session handle: %s' % str(token.session_handle)
        print 'session expiration: %s' % str(token.session_expires)
    else:
        print 'Access token never expires. Skipping ...' 
    pause()

def pause():
    print ''
    time.sleep(1)

if __name__ == '__main__':
    run_example()
    print 'Done.'