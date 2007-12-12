<?php
require_once("common.inc.php");

$test_server = new TestOAuthServer(new MockOAuthDataStore());
$sha1_method = new OAuthSignatureMethod_HMAC_SHA1();
$plaintext_method = new OAuthSignatureMethod_PLAINTEXT();
$test_server->add_signature_method($sha1_method);
$test_server->add_signature_method($plaintext_method);

try {
  $req = OAuthRequest::from_request();
  list($consumer, $token) = $test_server->verify_request($req);

  // lsit back the non-OAuth params
  $total = array();
  foreach($req->get_parameters() as $k => $v) {
    if (substr($k, 0, 5) == "oauth") continue;
    $total[] = urlencode($k) . "=" . urlencode($v);
  }
  print implode("&", $total);
} catch (OAuthException $e) {
  print($e->getMessage() . "\n<hr />\n");
  print_r($req);
  die();
}

?>
