<?php
namespace Exceptio\SSO;
final class ExceptioSSO{

	public $Apikey;
	public $siteUrl;
	public $protocol;
	public $host;
	public $salt;

	public function __construct($apikey, $salt = 445){
		$this->Apikey 	= $apikey;
		$this->siteUrl 	= "http://localhost/exceptiosso/public/";
		$this->protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
		$this->host 	= $_SERVER['HTTP_HOST'];
		$this->salt 	= $salt;
	}

	public function getAccessToken(){	

		$token = $this->makeRequest('get-access-token','GET',['origin' => $this->protocol.$this->host]);
		if($token->status && !isset($_COOKIE['APISID'])){
			setcookie('APISID', $token->payload->accessToken, time() + (60*60*24*365));
		}else if($token->status && isset($_COOKIE['APISID']) && $_COOKIE['APISID'] != $token->payload->accessToken){
			setcookie('APISID', $token->payload->accessToken, time() + (60*60*24*365));
		}

		return $token;
	}	

	public function verifyAccessToken($accessToken){

		$token = $this->makeRequest('verify-access-token','GET',['origin' => $this->protocol.$this->host, 'accessToken' => $accessToken]);
		if($token->error == 423){
			unset($_COOKIE['APISID']);
			setcookie('APISID', '', time() - 3600);
		}else if($token->status){
			$token->payload = json_decode($this->decrypt($token->payload));
		}

		return $token;
	}

	public function refreshAccessToken($accessToken){

		$token = $this->makeRequest('refresh-access-token','GET',['origin' => $this->protocol.$this->host, 'accessToken' => $accessToken]);
		if($token->error == 423){
			unset($_COOKIE['APISID']);
			setcookie('APISID', '', time() - 3600);
		}

		return $token;
	}

	public function logoutAccessToken($accessToken){

		$token = $this->makeRequest('logout-access-token','GET',['accessToken' => $accessToken]);
		if($token->status){
			unset($_COOKIE['APISID']);
			setcookie('APISID', '', time() - 3600);
		}

		return $token;
		
	}

	public function globalLogout($accessToken){		
		header('Location: '.$this->siteUrl.'user-logout?accessToken='.urlencode($accessToken));
	}

	public function encrypt($text, $salt = null) 
	{	
		$salt = ($salt) ? $salt : $this->salt;
		$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
		$iv = openssl_random_pseudo_bytes($ivlen);
		$ciphertext_raw = openssl_encrypt($text, $cipher, $salt, $options=OPENSSL_RAW_DATA, $iv);
		$hmac = hash_hmac('sha256', $ciphertext_raw, $salt, $as_binary=true);
		return base64_encode( $iv.$hmac.$ciphertext_raw );
	} 

	public function decrypt($text, $salt = null) 
	{
	    $salt = ($salt) ? $salt : $this->salt;
	    $c = base64_decode($text);
		$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
		$iv = substr($c, 0, $ivlen);
		$hmac = substr($c, $ivlen, $sha2len=32);
		$text_raw = substr($c, $ivlen+$sha2len);
		$original_plaintext = @openssl_decrypt($text_raw, $cipher, $salt, $options=OPENSSL_RAW_DATA, $iv);
		$calcmac = hash_hmac('sha256', $text_raw, $salt, $as_binary=true);
		if (@hash_equals($hmac, $calcmac))//PHP 5.6+ timing attack safe comparison
		{
		    return $original_plaintext;
		}

		return $text;
	}

	protected function makeRequest($url, $type = 'GET', $input = null, $heares = null){

		$curl = curl_init();
		$url = $this->siteUrl.'api/v1/'.$url;

		if($type == 'GET' && is_array($input) && count($input) > 0){
			$url .= '?'.http_build_query($input); 
		}
		$options = array(
		    CURLOPT_URL => $url,
		    CURLOPT_RETURNTRANSFER => true,
		    CURLOPT_ENCODING => "utf-8",
		    CURLOPT_MAXREDIRS => 10,
		    CURLOPT_TIMEOUT => 30000,
		    CURLOPT_CUSTOMREQUEST => $type,
		    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,		    		    
		    CURLOPT_HTTPHEADER => array(
		    	// Set here requred headers
		        "accept: */*",
		        "accept-language: en-US,en;q=0.8",
		        "content-type: application/json",
		        "Apikey: ".$this->Apikey
		    ),
		);
		//dd($options);
		if($type == 'POST' && is_array($input) && count($input) > 0){
			$options[CURLOPT_POST] = 1;			
			$options[CURLOPT_POSTFIELDS] = json_encode($input);			
		}

		curl_setopt_array($curl, $options);

		$response = curl_exec($curl);
		$err = curl_error($curl);

		curl_close($curl);		
		if ($err) {
		    return (object)[
		    	'status' 	=> 0,
		    	'error'		=> 1,
		    	'payload'	=> $err
		    ];
		} else {
			$data = json_decode($response);
 			if(json_last_error() == JSON_ERROR_NONE)
		    	return (object)$data;
		    else
		    	return (object)[
			    	'status' 	=> 0,
			    	'error'		=> 1,
			    	'payload'	=> $response
			    ];
		}
    }
}
// $ApiKey = "kSGNFNTCUQ12XISMfcSjyZz+xJCC3DiuaPo7Ty3dwK1kh94IScBRbYhKJHPfqEW/6EmnmDNfRUl18F5cKFqz6eO+9LnedE2g2ZPT9fBwc/RVU2DE5vwQqGqOPUx22+S1";
$ApiKey = "KZX2DxWmWN+B4M9IhPJHYA7e1H3NrlD1JzCMR/GrecyMt71dHYt+U5SL7DHa2pprur84PCXwy33Q7jxe2WVVKkFHGGBIiv9cb1frLhp5jmYTr2n+E+SW5IEwiFwfLSPE";
?>