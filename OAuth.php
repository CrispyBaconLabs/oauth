<?php
// vim: foldmethod=marker

/* Generic exception class
 */
class OAuthException extends Exception {/*{{{*/
  // pass
}/*}}}*/

class OAuthConsumer {/*{{{*/
  public $key;
  public $secret;
  public $callback_url;

  function __construct($key, $secret, $callback_url=NULL) {/*{{{*/
    $this->key = $key;
    $this->secret = $secret;
    $this->callback_url = $callback_url;
  }/*}}}*/
}/*}}}*/

class OAuthToken {/*{{{*/
  // access tokens and request tokens
  public $key;
  public $secret;
  public $authorized;
  public $data;

  function __construct($key, $secret, $authorized=FALSE, $data=NULL) {/*{{{*/
    $this->key = $key;
    $this->secret = $secret;
    $this->authorized = $authorized;
    $this->data = $data;
  }   /*}}}*/

  function to_string() {
    return "oauth_token=" . urlencode($this->key) . 
        "&oauth_token_secret=" . urlencode($this->secret);
  }
  function __toString() {
    return $this->to_string();
  }
}/*}}}*/

class OAuthRequest {/*{{{*/
  public $params;
  public $http_method;
  public $http_url;
  public $base_string;

  function __construct($params, $http_method, $http_url) {/*{{{*/
    $this->params = $params;
    $this->http_method = $http_method;
    $this->http_url = $http_url;
  }/*}}}*/

  function __get($name) {/*{{{*/
    return $this->params[$name];
  }/*}}}*/

  function __set($name, $value) {/*{{{*/
    $this->params[$name] = $value;
  }/*}}}*/

  public static function from_request($arr=NULL, $url=NULL, $method=NULL) {/*{{{*/
    @$url or $url = "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    @$method or $method = $_SERVER['REQUEST_METHOD'];
    // let the library user override things however they'd like
    //
    $request_headers = apache_request_headers();
    if ($arr) {
      $req = new OAuthRequest($arr, $method, $url);
    }
    // next check for the auth header, we need to do some extra stuff
    // if that is the case
    else if (@substr($request_headers['Authorization'], 0, 5) == "OAuth") {
      $header_params = OAuthRequest::split_header($request_headers['Authorization']);
      if ($method == "GET") {
        $req_params = $_GET;
      } 
      else if ($method = "POST") {
        $req_params = $_POST;
      } 
      $params = array_merge($header_params, $req_params);
      $req = new OAuthRequest($params, $method, $url);
    }
    else if ($method == "GET") {
      $req = new OAuthRequest($_GET, $method, $url);
    }
    else if ($method == "POST") {
      $req = new OAuthRequest($_POST, $method, $url);
    }
    return $req;
  }/*}}}*/

  function split_header($header) {/*{{{*/
    // this should be a regex
    // error cases: commas in parameter values
    $parts = explode(",", $header);
    $out = array();
    foreach ($parts as $param) {
      $param = ltrim($param);
      // skip the "realm" param
      if (substr($param, 0, 5) != "oauth") continue;
      $param_parts = explode("=", $param);
      $out[$param_parts[0]] = rawurldecode(substr($param_parts[1], 1, -1));
    }
    return $out;
  }/*}}}*/

  // normalization
  function signable_params() {/*{{{*/
    $sorted = $this->params;
    ksort($sorted);

    $total = array();
    foreach ($sorted as $k => $v) {
      if ($k == "oauth_signature") continue;
      $total[] = $k . "=" . $v;
      //$total[] = urlencode($k) . "=" . urlencode($v);
    }
    return implode("&", $total);
  }/*}}}*/

  function normalized_http_method() {/*{{{*/
    return strtoupper($this->http_method);
  }/*}}}*/

  function normalized_http_url() {/*{{{*/
    $parts = parse_url($this->http_url);
    $url_string = "{$parts['scheme']}://{$parts['host']}{$parts['path']}";
    return $url_string;
  }/*}}}*/

  function to_url() {/*{{{*/
    $out = $this->normalized_http_url() . "?";
    $out .= $this->to_postdata();
    return $out;
  }/*}}}*/

  function to_postdata() {/*{{{*/
    $total = array();
    foreach ($this->params as $k => $v) {
      $total[] = urlencode($k) . "=" . urlencode($v);
    }
    $out = implode("&", $total);
    return $out;
  }/*}}}*/

  function to_header() {/*{{{*/
    $out ='"Authorization: OAuth realm="",';
    $total = array();
    foreach ($this->params as $k => $v) {
      if (substr($k, 0, 5) != "oauth") continue;
      $total[] = urlencode($k) . '="' . urlencode($v) . '"';
    }
    $out = implode(",", $total);
    return $out;
  }/*}}}*/

  function __toString() {/*{{{*/
    return $this->to_url();
  }/*}}}*/

  /**
   * pretty much a helper function to set up the request
   */
  function build_request($consumer, $token) {/*{{{*/
    // set up some default bits
    @$this->oauth_version or $this->oauth_version = '1.0';
    @$this->oauth_nonce
        or $this->oauth_nonce = $this->generate_nonce();
    @$this->oauth_timestamp
        or $this->oauth_timestamp = $this->generate_timestamp();

    @$this->oauth_consumer_key
        or $this->oauth_consumer_key = $consumer->key;

    if ($token) {
      @$this->oauth_token
          or $this->oauth_token = $token->key;
    }

  }/*}}}*/

  function sign_request_HMAC_SHA1($consumer, $token) {/*{{{*/
    $this->oauth_signature_method = 'HMAC-SHA1';
    $this->oauth_signature = $this->build_signature_HMAC_SHA1(
      $consumer,
      $token
    );
  }/*}}}*/

  function build_signature_HMAC_SHA1($consumer, $token) {/*{{{*/
    $sig = array(
      urlencode($this->normalized_http_method()),
      urlencode($this->normalized_http_url()),
      urlencode($this->signable_params()),
      //urlencode($consumer->secret),
    );
    $key = $consumer->secret . "&";

    if ($token) {
      //array_push($sig, urlencode($token->secret));
      $key .= $token->secret;
    } else {
      //array_push($sig, '');
    }

    $raw = implode("&", $sig);
    $this->base_string = $raw;
    $hashed = base64_encode(hash_hmac("sha1", $raw, $key, TRUE));
    //$hashed = str_replace(".", "%2E", $hashed);
    return $hashed;
  } /*}}}*/

  function sign_request_PLAINTEXT($consumer, $token) {/*{{{*/
    $this->oauth_signature_method = 'PLAINTEXT';
    $this->oauth_signature = $this->build_signature_PLAINTEXT(
      $consumer,
      $token
    );
  }/*}}}*/

  function build_signature_PLAINTEXT($consumer, $token) {/*{{{*/
    $sig = array(
      urlencode($consumer->secret),
    );

    if ($token) {
      array_push($sig, urlencode($token->secret));
    } else {
      array_push($sig, '');
    }

    $raw = implode("&", $sig);
    return $raw;
  } /*}}}*/

  // generation
  function generate_timestamp() {/*{{{*/
    return time();
  }/*}}}*/

  function generate_nonce() {/*{{{*/
    $mt = microtime();
    $rand = mt_rand();

    return md5($mt . $rand); // md5s look nicer than numbers
  }/*}}}*/

}/*}}}*/

class OAuthServer {/*{{{*/
  public $timestamp_threshold = 300; // in seconds, five minutes
  public $version = 1.0;
  public $signature_methods = array(
    "PLAINTEXT",
    "HMAC-SHA1",
  );

  private $store;

  function __construct($store) {/*{{{*/
    $this->store = $store;
  }/*}}}*/

  function get_version(&$request) {/*{{{*/
    $version = @$request->oauth_version;
    if (!$version) {
      $version = 1.0;
    }
    if ($version && $version != $this->version) {
      throw new OAuthException("OAuth version '$version' not supported");
    }
    return $version;
  }/*}}}*/

  function get_signature_method(&$request) {/*{{{*/
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
  }/*}}}*/

  function get_consumer(&$request) {/*{{{*/
    $consumer_key = @$request->oauth_consumer_key;
    if (!$consumer_key) {
      throw new OAuthException("Invalid consumer key");
    }

    $consumer = $this->store->lookup_consumer($consumer_key);
    if (!$consumer) {
      throw new OAuthException("Invalid consumer");
    }

    return $consumer;
  }/*}}}*/

  function get_token(&$request, $consumer, $token_type="access") {/*{{{*/
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
  }/*}}}*/

  function check_signature(&$request, $consumer, $token) {/*{{{*/
    // this should probably be in a different method
    $timestamp = @$request->oauth_timestamp;
    $nonce = @$request->oauth_nonce;

    $this->check_timestamp($timestamp);
    $this->check_nonce($consumer, $token, $nonce, $timestamp);

    $signature_method = $this->get_signature_method($request);

    $signature_method_name =
      "check_signature_" . str_replace("-","_",$signature_method);

    $this->$signature_method_name($request, $consumer, $token);
  }/*}}}*/

  function check_signature_PLAINTEXT(&$request, $consumer, $token = NULL) {/*{{{*/
    // pass for now
    $signature = @$request->oauth_signature;

    $built = $request->build_signature_PLAINTEXT(
      $consumer, $token
    );

    if ($signature != $built) {
      throw new OAuthException("Invalid signature");
    }
  }/*}}}*/

  function check_signature_HMAC_SHA1(&$request, $consumer, $token) {/*{{{*/
    $signature = @$request->oauth_signature;

    $built = $request->build_signature_HMAC_SHA1(
      $consumer, $token
    );

    if ($signature != $built) {
      throw new OAuthException("Invalid signature");
    }
  }/*}}}*/

  function check_timestamp($timestamp) {/*{{{*/
    // verify that timestamp is recentish
    $now = time();
    if ($now - $timestamp > $this->timestamp_threshold) {
      throw new OAuthException("Expired timestamp, yours $timestamp, ours $now");
    }
  }/*}}}*/

  function check_nonce($consumer, $token, $nonce, $timestamp) {/*{{{*/
    // verify that the nonce is uniqueish
    $found = $this->store->lookup_nonce($consumer, $token, $nonce, $timestamp);
    if ($found) {
      throw new OAuthException("Nonce already used: $nonce");
    }
  }/*}}}*/


  // high level functions
  function request_token(&$request) {/*{{{*/
    $this->get_version($request);

    $consumer = $this->get_consumer($request);

    // no token required for the initial token request
    $token = NULL;

    $this->check_signature($request, $consumer, $token);

    $new_token = $this->store->new_request_token($consumer);

    return $new_token;
  }/*}}}*/

  function access_token(&$request) {/*{{{*/
    $this->get_version($request);

    $consumer = $this->get_consumer($request);

    // requires authorized request token
    $token = $this->get_token($request, $consumer, "request");

    $this->check_signature($request, $consumer, $token);

    $new_token = $this->store->new_access_token($token, $consumer);

    return $new_token;
  }/*}}}*/

  function verify_request(&$request) {/*{{{*/
    $this->get_version($request);
    $consumer = $this->get_consumer($request);
    $token = $this->get_token($request, $consumer, "access");
    $this->check_signature($request, $consumer, $token);
    return array($consumer, $token);
  }/*}}}*/

}/*}}}*/

class OAuthStore {/*{{{*/
  function lookup_consumer($consumer_key) {/*{{{*/
    // implement me
  }/*}}}*/

  function lookup_token($consumer, $token_type, $token) {/*{{{*/
    // implement me
  }/*}}}*/

  function lookup_nonce($consumer, $token, $nonce, $timestamp) {/*{{{*/
    // implement me
  }/*}}}*/

  function new_request_token($consumer) {/*{{{*/
    // return a new token attached to this consumer
  }/*}}}*/

  function new_access_token($token, $consumer) {/*{{{*/
    // return a new access token attached to this consumer
    // for the user associated with this token
    // should also invalidate the request token
  }/*}}}*/

}/*}}}*/


/*  A very naive dbm-based oauth storage
 */
class SimpleOAuthStore extends OAuthStore {/*{{{*/
  private $dbh;

  function __construct($path = "oauth.gdbm") {/*{{{*/
    $this->dbh = dba_popen($path, 'c', 'gdbm');
  }/*}}}*/

  function __destruct() {/*{{{*/
    dba_close($this->dbh);
  }/*}}}*/

  function lookup_consumer($consumer_key) {/*{{{*/
    $rv = dba_fetch("consumer_$consumer_key", $this->dbh);
    if ($rv === FALSE) {
      return NULL;
    }
    $obj = unserialize($rv);
    if (!($obj instanceof OAuthConsumer)) {
      return NULL;
    }
    return $obj;
  }/*}}}*/

  function lookup_token($consumer, $token_type, $token) {/*{{{*/
    $rv = dba_fetch("${token_type}_${token}", $this->dbh);
    if ($rv === FALSE) {
      return NULL;
    }
    $obj = unserialize($rv);
    if (!($obj instanceof OAuthToken)) {
      return NULL;
    }
    return $obj;
  }/*}}}*/

  function lookup_nonce($consumer, $token, $nonce, $timestamp) {/*{{{*/
    return dba_exists("nonce_$nonce", $this->dbh);
  }/*}}}*/

  function new_token($consumer, $type="request") {/*{{{*/
    $key = md5(time());
    $secret = time() + time();
    $token = new OAuthToken($key, md5(md5($secret)));
    if (!dba_insert("${type}_$key", serialize($token), $this->dbh)) {
      throw new OAuthException("doooom!");
    }
    return $token;
  }/*}}}*/

  function new_request_token($consumer) {/*{{{*/
    return $this->new_token($consumer, "request");
  }/*}}}*/

  function new_access_token($token, $consumer) {/*{{{*/

    $token = $this->new_token($consumer, 'access');
    dba_delete("request_" . $token->key, $this->dbh);
    return $token;
  }/*}}}*/
}/*}}}*/

?>
