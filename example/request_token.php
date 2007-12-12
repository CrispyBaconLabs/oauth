<?php
require_once("common.inc.php");

$test_server = new TestOAuthServer(new MockOAuthDataStore());
$sha1_method = new OAuthSignatureMethod_HMAC_SHA1();
$plaintext_method = new OAuthSignatureMethod_PLAINTEXT();
$test_server->add_signature_method($sha1_method);
$test_server->add_signature_method($plaintext_method);

try {
  $req = OAuthRequest::from_request();
  $token = $test_server->fetch_request_token($req);
  print $token;
} catch (OAuthException $e) {
  print($e->getMessage() . "\n<hr />\n");
  print_r($req);
  die();
}

?>
