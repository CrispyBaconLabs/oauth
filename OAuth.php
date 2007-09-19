<?php


class OAuthException extends Exception {
    // pass
}

class OAuthConsumer {
    public $key;
    public $secret;
    public $callback_url;

    function __construct($key, $secret, $callback_url) {
        $this->key = $key;
        $this->secret = $secret;
        $this->callback_url = $callback_url;
    }
}

class OAuthToken {
    public $key;
    public $secret;
    public $authorized;
    public $data;

    function __construct($key, $secret, $authorized=FALSE, $data=NULL) {
        $this->key = $key;
        $this->secret = $secret;
        $this->authorized = $authorized;
        $this->data = $data;
    }   
}

class OAuthRequest {
    public $params;
    public $http_method;
    public $http_url;

    function __construct($params, $http_method, $http_url) {
        $this->params = $params;
        $this->http_method = $http_method;
        $this->http_url = $http_url;
    }

    function __get($name) {
        return $this->params[$name];
    }

    function __set($name, $value) {
        $this->params[$name] = $value;
    }

    // normalization
    function normalized_params() {
        $sorted = $this->params;
        ksort($sorted);
        
        $total = array();
        foreach ($total as $k => $v) {
            if ($this->not_oauth($k)) {
                $total[] = $k . "=" . $v;
            }
        }
        return urlencode(implode("&", $total));
    }

    function normalized_http_method() {
        return strtoupper($this->http_method);
    }

    function normalized_http_url() {
        $parts = parse_url($this->http_url);
        $url_string = "{$parts['scheme']}://{$parts['host']}{$parts['path']}";
        return $url_string;
    }

    // signature building
    function build_signature_HMAC_SHA1(&$consumer, &$token, $timestamp=NULL, $nonce=NULL) {
        if ($timestamp == NULL) {
            $timestamp = $this->generate_timestamp();
        }
        
        if ($nonce == NULL) {
            $nonce = $this->generate_nonce();
        }

        $sig = array(
            $consumer->key,
            $consumer->secret,
        );
        if ($token) {
            array_push($sig, $token->key, $token->secret);
        } else {
            array_push($sig, '', '');
        }

        array_push(
            $sig, 
            $this->normalized_http_method(), 
            $this->normalized_http_url(),
            $this->normalized_params(),
            $timestamp,
            $nonce
        );

        $raw = implode("&", $sig);
        $hashed = hash_hmac("sha1", $raw, $consumer->secret);
        //$hashed = str_replace(".", "%2E", $hashed);
        return $hashed;
    } 


    // generation
    function generate_timestamp() {
        return time();
    }

    function generate_nonce() {
        $mt = microtime();
        $rand = mt_rand();
        
        return md5($mt . $rand); // md5s look nicer than numbers
    }

    // php sucks at map/filter
    function not_oauth($name) {
        return substr($name, 0, 5) != "oauth";
    }
}

class OAuthServer {
    public $timestamp_threshold = 300; // in seconds, five minutes
    public $version = 1.0;
    public $signature_methods = array(
        "PLAINTEXT",
        "HMAC-SHA1",
    );

    private $store;

    function __construct($store) {
        $this->store = $store;
    }

    function get_version(&$request) {
        $version = @$request->oauth_version;
        if (!$version) {
            $version = 1.0;
        }
        if ($version && $version >= $this->version) {
            throw new OAuthException("OAuth version '$version' not supported");
        }
        return $version;
    }

    function get_signature_method(&$request) {
        $signature_method = @$request->oauth_signature_method;
        if (!$signature_method) {
            $signature_method = "PLAINTEXT";
        }
        if (!in_array($signature_method, $this->signature_methods)) {
            throw new OAuthException(
                "Signature method '$signature_method' not supported try one of the following: " . implode(", ", $this->signature_methods)
            );      
        }
        return $signature_method;
    }


    function get_consumer(&$request) {
        $consumer_key = @$request->oauth_consumer_key;
        if (!$consumer_key) {
            throw new OAuthException("Invalid consumer key");
        }

        $consumer = $this->store->lookup_consumer($consumer_key);
        if (!$consumer) {
            throw new OAuthException("Invalid consumer");
        }

        return $consumer;
    }

    function get_token(&$request, &$consumer, $token_type="access") {
        $token_field = @$request->oauth_token;
        $token = $this->store->lookup_token(
            $consumer, $token_type, $token_field
        );
        if (!$token) {
            throw new OAuthException("Invalid $token_type token: $token_field");
        }
        if (!$token->authorized) {
            throw new OAuthException("Unauthorized  $token_type token: $token_field");
        }
        return $token;
    }

    function check_signature(&$request, &$consumer, &$token) {
        $signature_method = $this->get_signature_method();
        
        $signature_method_name = 
            "check_signature_" . str_replace("-","_",$signature_method);

        $this->$signature_method_name($request, $consumer, $token);
    }

    function check_signature_PLAINTEXT(&$request, &$consumer, &$token = NULL) {
        // pass for now
        $signature_raw = @$request->oauth_signature;
        list($consumer_secret, $token_secret) = array_map(
            array($this, "unescape_dots"), 
            explode(".", $signature_raw)
        );

        if (!$consumer_secret == $consumer->secret) {
            throw new OAuthException("Unable to verify consumer");   
        }

        if ($token) {
            if (!$token_secret == $token->secret) {
                throw new OAuthException("Unable to verify $token_type token");
            }
        }
    }

    function check_signature_HMAC_SHA1(&$request, &$consumer, &$token) {
        $signature = @$request->oauth_signature;
        $timestamp = @$request->oauth_ts;
        $nonce = @$request->oauth_nonce;

        //list($timestamp, $nonce, $signature) = array_map(
        //    array($this, "unescape_dots"), 
        //    explode(".", $signature_raw)
        //);

        $this->check_timestamp($timestamp);
        $this->check_nonce($consumer, $token, $nonce, $timestamp);

        $built = $request->build_signature_HMAC_SHA1(
            $request, $consumer, $token, $token, $timestamp
        );
        
        if ($signature != $built) {
            throw new OAuthException("Invalid signature");
        }
    }
    
    function check_timestamp($timestamp) {
        // verify that timestamp is recentish
        $now = time();
        if ($now - $timestamp > $this->timestamp_threshold) {
            throw new OAuthException("Expired timestamp, yours $timestamp, ours $now");
        }
    }

    function check_nonce(&$consumer, &$token, $nonce, $timestamp) {
        // verify that the nonce is uniqueish
        $found = $this->store->lookup_nonce($consumer, $token, $nonce, $timestamp);
        if ($found) {
            throw new OAuthException("Nonce already used: $nonce");
        }
    }

    
    // high level functions
    function request_token(&$request) {
        $this->get_version($request);
        
        $consumer = $this->get_consumer($request);

        // no token required for the initial token request
        $token = NULL;

        $this->check_signature($request, $consumer, $token);
        
        $new_token = $this->store->new_request_token($consumer);

        return $new_token;
    }

    function access_token(&$request) {
        $this->get_version($request);
        
        $consumer = $this->get_consumer($request);
        
        // requires authorized request token
        $token = $this->get_token($request, $consumer, "request");

        $this->check_signature($request, $consumer, $token);
        
        $new_token = $this->store->new_access_token($token, $consumer);

        return $new_token;
    }

    function verify_request(&$request) {
        $this->get_version($request);
        $consumer = $this->get_consumer($request);
        $token = $this->get_token($request, $consumer, "access");
        $this->check_signature($request, $consumer, $token);
        return array($consumer, $token);
    }

    // php sucks at map/filter
    function unescape_dots($s) {
        // this dot escaping is obviously a bit flawed, however it isn't
        // really expected that people will put overly complex
        // escaped other things in these hashes for now
        return str_replace("%2E", ".", $s);
    }
}


class OAuthStore {
    function lookup_consumer($consumer_key) {
        // implement me
    }

    function lookup_token(&$consumer, $token_type, $token) {
        // implement me
    }

    function lookup_nonce(&$consumer, &$token, $nonce, $timestamp) {
        // implement me
    }

    function new_request_token(&$consumer) {
        // return a new token attached to this consumer
    }

    function new_access_token(&$token, &$consumer) {
        // return a new access token attached to this consumer
        // for the user associated with this token
        // should also invalidate the request token
    }

}


?>
