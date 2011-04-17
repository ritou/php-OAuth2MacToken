<?php

/**
 * OAuth 2.0 MAC Token : Sample Resource Server
 */
include("OAuth2MacTokenServer.php");

// Valid MAC Credentials
$token = "tokenstring";
$secret = "secretstring";
$algorithm = "hmac-sha-1";

// Configration
$validSecond = 600;
$invalidNonce = "invalidnonce";

// Set Content-Type
header('Content-Type: text/plain');

// OAuth 2.0 : Resource Server Process
$server = new OAuth2MacTokenServer();
// 1. Check required parameters
if (!$server->getStatus()) {
    header($server->getHttpResponseAuthNHeader());
    header($server->getHttpResponseCode());
    exit;
}

// 2. Check bodyhash
$server->setAlgorithm('hmac-sha-1');
$server->validateBodyHash();
if (!$server->getStatus()) {
    header($server->getHttpResponseAuthNHeader());
    header($server->getHttpResponseCode());
    exit;
}

// 3. Check token
//    This process is out of scope of this library.
if ($token != $server->getToken()) {
    $server->setHttpResponseCode("HTTP/1.1 401 Unauthorized");
    $server->setHttpResponseError("invalid_token");
    header($server->getHttpResponseAuthNHeader());
    header($server->getHttpResponseCode());
    exit;
}

// 4. Check signature
$server->setSecret($secret);
$server->validateSignature();
if (!$server->getStatus()) {
    header($server->getHttpResponseAuthNHeader());
    header($server->getHttpResponseCode());
    exit;
}

// 5. Check timestamp
$server->validateTimestamp($validSecond);
if (!$server->getStatus()) {
    header($server->getHttpResponseAuthNHeader());
    header($server->getHttpResponseCode());
    exit;
}

// 6. Check nonce
//    This process is out of scope of this library.
if ($invalidNonce == $server->getNonce()) {
    $server->setHttpResponseCode("HTTP/1.1 400 Bad Request");
    $server->setHttpResponseError("invalid_nonce");
    header($server->getHttpResponseAuthNHeader());
    header($server->getHttpResponseCode());
    exit;
}

// Other Process
// ex) Check method
//    $method = $server->getMethod();
//    This process is out of scope of this library.
print "Success";