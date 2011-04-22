<?php
/**
 * OAuth 2.0 MAC Token : Sample Client
 */
include("OAuth2MacTokenClient.php");

// Sample 1. GET
// MAC Credential
$token = "tokenstring";
$secret = "secretstring";
$algorithm = "hmac-sha-1";

$nonce = "validnonce";
$method = "GET";
$url = "http://" . $_SERVER["HTTP_HOST"] . ':' . $_SERVER["SERVER_PORT"] . str_replace("clientsample", "serversample", $_SERVER["SCRIPT_NAME"]) . "?param1=value1&param2=value2";

$mac = new OAuth2MacTokenClient($token, $secret, $algorithm);
//$mac->setTimestamp($timestamp);
$mac->setNonce($nonce);
$mac->enableResponseHeader(); // for debug
$mac->sendRequest($method, $url);
$response = $mac->getLastResponse();
$header = $mac->getLastRequestHeader();

$display = <<<EOF
========== Sample 1. GET Request ==========
- Parameters
 - method : {$method}
 - token : {$token}
 - secret : {$secret}
 - algorithm : {$algorithm}
 - timestamp : (current time)
 - nonce : {$nonce}
 - url : {$url}
 - entitybody : {$entitybody}
--------------------------------------------
- Request Header
{$header}
--------------------------------------------
- Response
{$response}
--------------------------------------------

EOF;

// Sample 2. POST
$token = "tokenstring";
$secret = "secretstring";
$algorithm = "hmac-sha-1";
$nonce = "validnonce";
$method = "POST";
$url = "http://" . $_SERVER["HTTP_HOST"] . ':' . $_SERVER["SERVER_PORT"] . str_replace("clientsample", "serversample", $_SERVER["SCRIPT_NAME"]) . "?param1=value1&param2=value2";
$entitybody = "postkey1=postvalue1";
$headers = array('Content-Type: application/x-www-form-urlencoded');

$mac = new OAuth2MacTokenClient($token, $secret, $algorithm);
//$mac->setTimestamp($timestamp);
$mac->setNonce($nonce);
$mac->enableResponseHeader(); // for debug
$mac->sendRequest($method, $url, $entitybody, $headers);
$response = $mac->getLastResponse();
$header = $mac->getLastRequestHeader();

$display .= <<<EOF
========== Sample 2. POST Request ==========
- Parameters
 - method : {$method}
 - token : {$token}
 - secret : {$secret}
 - algorithm : {$algorithm}
 - timestamp : (current time)
 - nonce : {$nonce}
 - url : {$url}
 - entitybody : {$entitybody}
--------------------------------------------
- Request Header
{$header}
--------------------------------------------
- Response
{$response}
--------------------------------------------

EOF;

// Sample 3. POST
$token = "tokenstring";
$secret = "secretstring";
$algorithm = "hmac-sha-1";
$nonce = "validnonce";
$method = "POST";
$url = "http://" . $_SERVER["HTTP_HOST"] . ':' . $_SERVER["SERVER_PORT"] . str_replace("clientsample", "serversample", $_SERVER["SCRIPT_NAME"]);
$entitybody = "post-entity-body-string";
$headers = array('Content-Type: text/plain; charset=UTF-8');

$mac = new OAuth2MacTokenClient($token, $secret, $algorithm);
//$mac->setTimestamp($timestamp);
$mac->setNonce($nonce);
$mac->enableResponseHeader(); // for debug
$mac->sendRequest($method, $url, $entitybody, $headers);
$response = $mac->getLastResponse();
$header = $mac->getLastRequestHeader();

$display .= <<<EOF
========== Sample 3. POST Request ==========
- Parameters
 - method : {$method}
 - token : {$token}
 - secret : {$secret}
 - algorithm : {$algorithm}
 - timestamp : (current time)
 - nonce : {$nonce}
 - url : {$url}
 - entitybody : {$entitybody}
--------------------------------------------
- Request Header
{$header}
--------------------------------------------
- Response
{$response}
--------------------------------------------

EOF;

?>
<html>
    <body>
        <pre>
<?php print htmlspecialchars($display); ?>
        </pre>
    </body>
</html> 
