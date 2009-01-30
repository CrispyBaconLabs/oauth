<?php

require dirname(__FILE__).'/../OAuth.php';
require_once 'PHPUnit/Framework.php';

/**
 * A simple utils class for methods needed
 * during some of the tests
 */
class OAuthTestUtils {
	private static function reset_request_vars() {
		$_SERVER = array();
		$_POST = array();
		$_GET = array();	
	}

	/**
	 * Populates $_{SERVER,GET,POST}
	 *
	 * TODO: Should query-string params always be added to $_GET.. prolly..
	 * 
	 * @param string $method GET or POST
	 * @param string $uri What URI is the request to (eg http://example.com/foo?bar=baz)
	 * @param array $params What params should go with the request
	 * @param string $auth_header What to set the Authorization header to
	 */
	public static function build_request( $method, $uri, $params, $auth_header = '' ) {
		self::reset_request_vars();

		$method = strtoupper($method);

		$parts = parse_url($uri);

	    $port = @$parts['port'];
	    $scheme = $parts['scheme'];
	    $host = $parts['host'];
	    $path = @$parts['path'];
		$query = @$parts['query'];

	    $port or $port = ($scheme == 'https') ? '443' : '80';

		if( $scheme == 'https') {
			$_SERVER['HTTPS'] = 'on';
		}

		$_SERVER['REQUEST_METHOD'] = $method;
		$_SERVER['HTTP_HOST'] = $host;
		$_SERVER['SERVER_PORT'] = $port;
		$_SERVER['REQUEST_URI'] = $path . '?' . $query;

		if( $method == 'POST' ) {
			$_SERVER['HTTP_CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
			$_POST = $params;
		} else {
			$_GET = $params;
		}
		
		if( $auth_header != '' ) {
			$_SERVER['HTTP_AUTHORIZATION'] = $auth_header;
		}
	}
}
