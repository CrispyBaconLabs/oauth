<?php
require_once("common.inc.php");

$test_server = new TestOAuthServer(new MockOAuthDataStore());

try {
  $req = OAuthRequest::from_request();
  list($consumer, $token) = $test_server->verify_request($req);
  
  // lsit back the non-OAuth params
  $total = array();
  foreach($req->params as $k => $v) {
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
