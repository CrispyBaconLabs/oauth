<?php

require_once 'OAuth.php';


class OAuthProblem extends OAuthException {
	// just need to differentiate from the kind of exceptions
	// that are automatically recoverable from and the kind
	// that aren't
	
	public $params;
	public $resp;
	
	function __construct($params) {
		$this->resp = $params;
		parse_str($params,$this->params);
		parent::__construct($this->params['oauth_problem']);
	}
}

class OAuthClient {
	public $consumer_key;
	public $consumer_secret;
	public $access_token;
	public $access_token_secret;
	public $signature_method;
	
	function __construct($consumer_key,$consumer_secret,$signature_method="HMAC-SHA1",$access_token=null,$access_token_secret) {
		$this->consumer_key = $consumer_key;
		$this->consumer_secret = $consumer_secret;
		$this->access_token = $access_token;
		$this->access_token_secret = $access_token_secret;
		$this->signature_method = $signature_method;
	}
	
	public function getAuthorizeUrl() {
		
	}
	
	protected function getRequestToken($endpoint, $http_method = "GET", $additional_parameters = null) {
		@$additional_parameters or $additional_parameters = array();
   		
		return $this->request($endpoint,$http_method,$additional_parameters);
	}
	
	protected function request($endpoint, $method, $additional_parameters) {
		$consumer = new OAuthConsumer($this->consumer_key,$this->consumer_secret);
  		$parsed = parse_url($endpoint);
  		$params = array();
  		
  		if(!empty($parsed['query'])) {
  			parse_str($parsed['query'], $params);
  		}
  		
  		$additional_parameters = array_merge($params, $additional_parameters);
  		
		for($i = 0; $i < 3 && empty($resp); $i++) {
			try {
				$req = OAuthRequest::from_consumer_and_token(
					$consumer,
					null,
					$method,
					$endpoint,
					$additional_parameters
					);
				
				$req->sign_request($this->signature_method,$consumer,null);
				$resp = null;

				$ch = null;
				$url = $req->to_url();
				if($method == "POST") {
					list($url,$vals) = split("\?",$url,2);
					$ch = curl_init($url);
					curl_setopt($ch, CURLOPT_POST, true);
					curl_setopt($ch, CURLOPT_POSTFIELDS, $vals);
				} else {
					$ch = curl_init($url);
				}
				
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
				curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
				curl_setopt($ch, CURLINFO_HEADER_OUT, true);
				
				$resp = curl_exec($ch);
				$error = curl_error($ch);
				$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
				$headers = curl_getinfo($ch,CURLINFO_HEADER_OUT);
				
				// TODO: check headers for oauth_problem, too
				if(int($status) != 200 || stripos($resp, "oauth_problem=")) {
					if(stripos($resp, "oauth_problem=")) {
						throw new OAuthProblem($resp);
					} else {
						throw new OAuthException($resp);
					}
				}
				
				return $resp;
			} catch (OAuthProblem $e) {
				switch($e->getMessage()) {
					case 'nonce_used':
					// let's assume the next rand will be ok...
						break;
					case 'timestamp_refused':
						if(!empty($e->params['oauth_acceptable_timestamps'])) {
							list(,$additiona_parameters['oauth_timestamp']) = explode("-",$e->params['oauth_acceptable_timestamps']);
						}
						break;
					case 'token_expired':
						throw $e;
					case 'token_rejected':
						throw $e;
					default:
						throw new OAuthException($e->resp);
				}
			}
		}
	}
	
}






?>
