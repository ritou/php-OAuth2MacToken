# php-OAuth2MacToken

This is MAC Access Authentication Utility Class Library for OAuth 2.0.
This library is free software.

## Files

*   lib/OAuth2MacTokenUtil.php       : Calcurate MAC, and Generate AuthZ Header String

## Usage

This is sample code using this library.

	include_once("lib/OAuth2MacTokenUtil.php");

	$key_id = "samplekeyid";
	$key = "samplekey";
	$algorithm = "hmac-sha-1";
	$iss = time() - 1; // dummy
	$nonce = "";
	$method = "GET";
	$url = "http://example.com:80/request?foo=var";
	$entitybody = "";
	$ext = "a,b,c";

	print <<< EOF
	=== Input Parameters ===
	key_id = "{$key_id}";
	key = "{$key}";
	algorithm = "{$algorithm}";
	iss = {$iss}; // dummy
	nonce = "{$nonce}";
	method = "{$method}";
	url = "{$url}";
	entitybody = "{$entitybody}";
	ext = "{$ext}";
	=== Input Parameters ===
	EOF;

	print "\n";

	print OAuth2MacTokenUtil::genetateAuthZHeader(
	                $key_id,
	                $key,
	                $algorithm,
	                $iss,
	                $nonce,
	                $method,
	                $url,
	                $entitybody,
	                $ext
	);

Sample is here.
[sample.php](http://www8322u.sakura.ne.jp/php-OAuth2MacToken/sample.php)

## Author

*   [@ritou](http://twitter.com/ritou)
*   [Blog](http://d.hatena.ne.jp/ritou)
*   ritou.06 _at_ gmail.com

## References

*   [IETF WG : OAuth 2.0](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/)
*   [HTTP Authentication: MAC Access Authentication](http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-00)
*   [Blog : MAC Access Authenticationの仕様をキャッチアップ (Japanese)](http://d.hatena.ne.jp/ritou/20110515/1305396837)