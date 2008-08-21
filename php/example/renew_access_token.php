<?php
require_once("common.inc.php");

try {
  $req = OAuthRequest::from_request();
  $token = $test_server->refresh_access_token($req);

  print $token;
} catch (OAuthException $e) {
  print $e->getMessage();
}

?>
