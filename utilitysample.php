<?php

include("lib/OAuth2MacTokenUtil.php");

//===========================================
// Sample A. GET
//===========================================

// Params
$token = "h480djs93hd8";
$secret = "489dks293j39";
$algorithm = "hmac-sha-1";
$timestamp = 137131200;
$nonce = "dj83hs9s";

// Resource Server Info
$method = "GET";
$url = "http://example.com/resource/1?b=1&a=2";

$AuthZHeader = OAuth2MacTokenUtil::genetateAuthZHeader($token, $secret, $algorithm, $timestamp, $nonce, $method, $url );
$display .= "===== Sample A. GET =====\n\n\n";
$display .= "Access Token : ".$token."\n";
$display .= "Secret : ".$secret."\n";
$display .= "Algorithm : ".$algorithm."\n";
$display .= "timestamp : ".$timestamp."\n";
$display .= "nonce : ".$nonce."\n";
$display .= "Method : ".$method."\n";
$display .= "URL : ".$url."\n";
$display .= "EntityBody : ".$entitybody."\n";
$display .= "AuthZ Header : ".$AuthZHeader."\n";
$display .= "===== Sample A. GET =====\n\n\n";

//===========================================
// Sample B. POST
//===========================================

// Params
$token = "j92fsdjf094gjfdi";
$secret = "8yfrufh348h";
$algorithm = "hmac-sha-1";
$timestamp = 137131206;
$nonce = "f403hksd";

// Resource Server Info
$method = "POST";
$url = "http://example.com/request";
$entitybody = "hello=world%21";

$AuthZHeader = OAuth2MacTokenUtil::genetateAuthZHeader($token, $secret, $algorithm, $timestamp, $nonce, $method, $url, $entitybody);
$display .= "===== Sample B. POST =====\n";
$display .= "Access Token : ".$token."\n";
$display .= "Secret : ".$secret."\n";
$display .= "Algorithm : ".$algorithm."\n";
$display .= "timestamp : ".$timestamp."\n";
$display .= "nonce : ".$nonce."\n";
$display .= "Method : ".$method."\n";
$display .= "URL : ".$url."\n";
$display .= "EntityBody : ".$entitybody."\n";
$display .= "AuthZ Header : ".$AuthZHeader."\n";
$display .= "===== Sample B. POST =====\n\n\n";

?>
<html>
    <body>
        <pre>
<?php print htmlspecialchars($display); ?>
        </pre>
    </body>
</html>