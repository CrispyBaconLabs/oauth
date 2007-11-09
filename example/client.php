<?php
require_once("common.inc.php");


$key = @$_REQUEST['key'];
$secret = @$_REQUEST['secret'];
$token = @$_REQUEST['oauth_token'];
$token_secret = @$_REQUEST['oauth_token_secret'];
$endpoint = @$_REQUEST['endpoint'];
$action = @$_REQUEST['action'];

$test_consumer = new OAuthConsumer($key, $secret, NULL);

$test_token = NULL;
if ($token) {
  $test_token = new OAuthConsumer($token, $token_secret);
}


if ($action == "request_token") {
  $req_req = new OAuthRequest(array(), "GET", $endpoint);
  $req_req->build_request($test_consumer, NULL);
  $req_req->sign_request_HMAC_SHA1($test_consumer, NULL);
  Header("Location: $req_req");
}


$acc_token = new OAuthConsumer("accesskey", "accesssecret", 1);

$req_req = new OAuthRequest(array(), "GET", $base_url . "/request_token.php");
$req_req->build_request($test_consumer, NULL);
$req_req->sign_request_HMAC_SHA1($test_consumer, NULL);

$acc_req = new OAuthRequest(array(), "GET", $base_url . "/access_token.php");
$acc_req->build_request($test_consumer, $req_token);
$acc_req->sign_request_HMAC_SHA1($test_consumer, $req_token);

$echo_req = new OAuthRequest(array("method"=> "foo", "bar" => "baz"), "GET", $base_url . "/echo_api.php");
$echo_req->build_request($test_consumer, $acc_token);
$echo_req->sign_request_HMAC_SHA1($test_consumer, $acc_token);

?>
<html>
<head>
<title>OAuth Test Client</title>
</head>
<body>
<h1>OAuth Test Client</h1>
<h2>Instructions for Use</h2>
<p>This is a test client that will let you test your OAuth server code. Enter the appropriate information below to test.</p>

<form method="POST" name="oauth_client">
<h3>Enter The Endpoint to Test</h3>
endpoint: <input type="text" name="endpoint" value="<?php echo $endpoint; ?>" /><br />
<h3>Enter Your Consumer Key / Secret</h3>
consumer key: <input type="text" name="key" value="<?php echo $key; ?>" /><br />
consumer secret: <input type="text" name="secret" value="<?php echo $secret;?>" /><br />
make a token request (don't forget to copy down the values you get)
<input type="submit" name="action" value="request_token" />

<h3>Currently Supported Signature Methods</h3>
<ul>
<?php
foreach ($test_server->signature_methods as $method) {
  print "<li>$method</li>\n";
}
?>
</ul>

<h3>Further Resources</h3>
<p>The code running this example can be downloaded from the PHP section of the OAuth google code project: <a href="http://code.google.com/p/oauth/">http://code.google.com/p/oauth/</a>
</body>
