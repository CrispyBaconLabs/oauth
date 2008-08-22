from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import urllib

import oauth

REQUEST_TOKEN_URL = 'http://pureshape.corp.yahoo.com/request_token'
ACCESS_TOKEN_URL = 'http://pureshape.corp.yahoo.com/access_token'
RENEW_ACCESS_TOKEN_URL = 'http://pureshape.corp.yahoo.com/renew_access_token'
AUTHORIZATION_URL = 'http://pureshape.corp.yahoo.com/authorize'
RESOURCE_URL = 'http://pureshape.corp.yahoo.com/photos'
REALM = 'http://pureshape.corp.yahoo.com/'

# example store for one of each thing
class MockOAuthDataStore(oauth.OAuthDataStore):
    def __init__(self):
        self.consumer = oauth.OAuthConsumer('key', 'secret')
        self.request_token = oauth.OAuthToken('requestkey', 'requestsecret', 3600)
        self.access_token = oauth.OAuthToken('accesskey', 'accesssecret', 3600, 'sessionhandle', 3600)
        self.nonce = 'nonce'

    def lookup_consumer(self, key):
        if key == self.consumer.key:
            return self.consumer
        return None

    def lookup_token(self, token_type, token):
        token_attrib = getattr(self, '%s_token' % token_type)
        if token == token_attrib.key:
            return token_attrib
        return None

    def lookup_nonce(self, oauth_consumer, oauth_token, nonce):
        if oauth_token and oauth_consumer.key == self.consumer.key and (oauth_token.key == self.request_token.key or oauth_token.key == self.access_token.key) and nonce == self.nonce:
            return self.nonce
        return None

    def fetch_request_token(self, oauth_consumer):
        if oauth_consumer.key == self.consumer.key:
            return self.request_token
        return None

    def fetch_access_token(self, oauth_consumer, oauth_token):
        if oauth_consumer.key == self.consumer.key and oauth_token.key == self.request_token.key:
            # want to check here if token is authorized
            # for mock store, we assume it is
            return self.access_token
        return None
    
    def renew_access_token(self, oauth_consumer, oauth_token):
        if oauth_consumer.key == self.consumer.key and oauth_token.key == self.access_token.key and oauth_token.session_handle == self.access_token.session_handle:
            # Want to check here for token expiration
            # Also should make sure the new token is returned with a fresh expiration
            # for mock store, the old token is returned
            return self.access_token
        return None

    def authorize_request_token(self, oauth_token, user):
        if oauth_token.key == self.request_token.key:
            # authorize the request token in the store
            # for mock store, do nothing
            return self.request_token
        return None

class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.oauth_server = oauth.OAuthServer(MockOAuthDataStore())
        self.oauth_server.add_signature_method(oauth.OAuthSignatureMethod_PLAINTEXT())
        self.oauth_server.add_signature_method(oauth.OAuthSignatureMethod_HMAC_SHA1())
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    # example way to send an oauth error
    def send_oauth_error(self, err=None):
        # send a 401 error
        self.send_error(401, str(err.message))
        # return the authenticate header
        header = oauth.build_authenticate_header(realm=REALM)
        for k, v in header.iteritems():
            self.send_header(k, v) 

    def do_GET(self):

        # debug info
        #print self.command, self.path, self.headers
        
        # get the post data (if any)
        postdata = None
        if self.command == 'POST':
            try:
                length = int(self.headers.getheader('content-length'))
                postdata = self.rfile.read(length)
            except:
                pass

        # construct the oauth request from the request parameters
        oauth_request = oauth.OAuthRequest.from_request(self.command, self.path, headers=self.headers, query_string=postdata)

        # request token
        if self.path.startswith(REQUEST_TOKEN_URL):
            try:
                # create a request token
                token = self.oauth_server.fetch_request_token(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the token
                self.wfile.write(token.to_string())
            except oauth.OAuthError, err:
                self.send_oauth_error(err)
            return

        # user authorization
        if self.path.startswith(AUTHORIZATION_URL):
            try:
                # get the request token
                token = self.oauth_server.fetch_request_token(oauth_request)
                callback = self.oauth_server.get_callback(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the callback url (to show server has it)
                self.wfile.write('callback: %s' % callback)
                # authorize the token (kind of does nothing for now)
                token = self.oauth_server.authorize_token(token, None)
                self.wfile.write('\n')
                # return the token key
                token_key = urllib.urlencode({'oauth_token': token.key})
                self.wfile.write('token key: %s' % token_key)
            except oauth.OAuthError, err:
                self.send_oauth_error(err)
            return

        # access token
        if self.path.startswith(ACCESS_TOKEN_URL):
            try:
                # create an access token
                token = self.oauth_server.fetch_access_token(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the token
                self.wfile.write(token.to_string())
            except oauth.OAuthError, err:
                self.send_oauth_error(err)
            return
        
        # renew token
        if self.path.startswith(RENEW_ACCESS_TOKEN_URL):
            try:
                token = self.oauth_server.refresh_access_token(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the token
                self.wfile.write(token.to_string())
            except oauth.OAuthError, err:
                self.send_oauth_error(err)
            return

        # protected resources
        if self.path.startswith(RESOURCE_URL):
            try:
                # verify the request has been oauth authorized
                consumer, token, params = self.oauth_server.verify_request(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the extra parameters - just for something to return
                self.wfile.write(str(params))
            except oauth.OAuthError, err:
                self.send_oauth_error(err)
            return

    def do_POST(self):
        return self.do_GET()

def main():
    try:
        server = HTTPServer(('', 8080), RequestHandler)
        print 'Test server running...'
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()

if __name__ == '__main__':
    main()