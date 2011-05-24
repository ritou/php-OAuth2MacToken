<?php

include_once("lib/OAuth2MacTokenUtil.php");
header("Content-Type: text/plain");

$key_id = "h480djs93hd8";
$key = "489dks293j39";
$algorithm = "hmac-sha-1";
$iss = strtotime("Thu, 02 Dec 2010 21:39:45 GMT");
$nonce = "264095:dj83hs9s";
$method = "GET";
$url = "http://example.com:80/resource/1?b=1&a=2";
$entitybody = "";
$ext = "";

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

print "\n\n";

$key_id = "jd93dh9dh39D";
$key = "8yfrufh348h";
$algorithm = "hmac-sha-1";
$iss = strtotime("Thu, 02 Dec 2010 21:39:45 GMT"); // dummy
$nonce = "273156:di3hvdf8";
$method = "POST";
$url = "http://example.com:80/request";
$entitybody = "hello=world%21";
$ext = "";

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

print "\n\n";

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

print "\n\n";

