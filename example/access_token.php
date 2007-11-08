<?php
require_once("common.inc.php");

$test_server = new TestOAuthServer(new MockOAuthStore());

try {
  $req = OAuthRequest::from_request();
  $token = $test_server->access_token($req);
  print $token;
} catch (OAuthException $e) {
  print($e->getMessage() . "\n<hr />\n");
  print_r($req);
  die();
}

?>
