<?php
require_once("common.inc.php");

$test_server = new TestOAuthServer(new MockOAuthDataStore());

try {
  $req = OAuthRequest::from_request();
  $token = $test_server->request_token($req);
  print $token;
} catch (OAuthException $e) {
  print($e->getMessage() . "\n<hr />\n");
  print_r($req);
  die();
}

?>
