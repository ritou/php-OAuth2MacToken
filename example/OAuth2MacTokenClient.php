<?php

include_once("../lib/OAuth2MacTokenUtil.php");

/**
 * OAuth 2.0 MAC Token Client Class
 */
class OAuth2MacTokenClient {

    // Client Credential
    private $_client_id;
    private $_client_secret;
    private $_redirect_uri;
    // MAC Token Info
    private $_token;
    private $_secret;
    private $_algorithm;
    private $_iss;
    private $_timestamp = null;
    private $_nonce = null;
    // CURL Info
    private $_useragent = 'OAuth2MacTokenClient v0.0.1';
    private $_timeout = 3;
    private $_connecttimeout = 3;
    private $_ssl_verifypeer = TRUE;
    private $_ssl_verifyhost = TRUE;
    private $_responseheader = FALSE;
    // CURL response
    private $_http_body = null;
    private $_http_code = null;
    private $_http_info = null;

    public function __construct($client_id, $client_secret, $redirect_uri) {
        $this->_client_id = $client_id;
        $this->_client_secret = $client_secret;
        $this->_redirect_uri = $redirect_uri;
    }

    public function getRequestAuthUrl($authz_endpoint) {
        return $authz_endpoint . "?client_id=" . urlencode($this->_client_id) . "&redirect_uri=" . urlencode($this->_redirect_uri) . "&response_type=code";
    }

    public function getAccessToken($token_endpoint, $code) {
        $params = array(
            "grant_type" => "authorization_code",
            "code" => $code,
            "redirect_uri" => $this->_redirect_uri,
            "client_id" => $this->_client_id,
            "client_secret" => $this->_client_secret
        );
        $this->_http_info = array();
        $this->_http_code = null;
        $this->_http_body = null;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_endpoint);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->_useragent);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->_connecttimeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->_timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->_ssl_verifypeer);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->_ssl_verifyhost);
        curl_setopt($ch, CURLOPT_HEADER, $this->_responseheader);
        curl_setopt($ch, CURLINFO_HEADER_OUT, TRUE);
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);

        $this->_http_body = curl_exec($ch);
        $this->_http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->_http_info = array_merge($this->_http_info, curl_getinfo($ch));
        curl_close($ch);
        return json_decode($this->_http_body);
    }

    public function refreshAccessToken($token_endpoint, $refresh_token) {
        $params = array(
            "grant_type" => "refreshAccessToken",
            "refresh_token" => $refresh_token,
            "client_id" => $this->_client_id,
            "client_secret" => $this->_client_secret
        );
        $this->_http_info = array();
        $this->_http_code = null;
        $this->_http_body = null;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_endpoint);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->_useragent);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->_connecttimeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->_timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->_ssl_verifypeer);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->_ssl_verifyhost);
        curl_setopt($ch, CURLOPT_HEADER, $this->_responseheader);
        curl_setopt($ch, CURLINFO_HEADER_OUT, TRUE);
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);

        $this->_http_body = curl_exec($ch);
        $this->_http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->_http_info = array_merge($this->_http_info, curl_getinfo($ch));
        curl_close($ch);
        return json_decode($this->_http_body);
    }

    public function setMacTokenCredential($token, $secret, $algorithm='hmac-sha1', $iss) {
        $this->_token = $token;
        $this->_secret = $secret;
        $this->_algorithm = $algorithm;
        $this->_iss = $iss;
        return true;
    }

    public function setTimestamp($timestamp) {
        if (!is_numeric($timestamp)) {
            return false;
        }
        $this->_timestamp = $timestamp;
        return true;
    }

    public function setNonce($nonce) {
        if (empty($nonce)) {
            return false;
        }
        $this->_nonce = $nonce;
        return true;
    }

    public function setTimeout($timeoutsec) {
        if (is_numeric($timestamp)) {
            $this->_timeout = $timeoutsec;
        }
    }

    public function setConnectTimeout($ctimeoutsec) {
        if (is_numeric($ctimestamp)) {
            $this->_connecttimeout = $ctimeoutsec;
        }
    }

    public function disableSSLChecks() {
        $this->_ssl_verifypeer = false;
        $this->_ssl_verifyhost = false;
    }

    public function enableSSLChecks() {
        $this->_ssl_verifypeer = true;
        $this->_ssl_verifyhost = true;
    }

    public function disableResponseHeader() {
        $this->_responseheader = false;
    }

    public function enableResponseHeader() {
        $this->_responseheader = true;
    }

    public function sendRequest($method, $url, $entitybody=null, $ext=null, $headers = array()) {

        $headers[] = OAuth2MacTokenUtil::genetateAuthZHeader($this->_token, $this->_secret, $this->_algorithm, $this->_iss, $this->_nonce, $method, $url, $entitybody, $ext);

        $this->_http_info = array();
        $this->_http_code = null;
        $this->_http_body = null;
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->_useragent);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->_connecttimeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->_timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->_ssl_verifypeer);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->_ssl_verifyhost);
        curl_setopt($ch, CURLOPT_HEADER, $this->_responseheader);
        curl_setopt($ch, CURLINFO_HEADER_OUT, TRUE);

        switch ($method) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, TRUE);
                if (!empty($entitybody)) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $entitybody);
                }
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if (!empty($entitybody)) {
                    $url = "{$url}?{$entitybody}";
                }
        }

        $this->_http_body = curl_exec($ch);
        $this->_http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->_http_info = array_merge($this->_http_info, curl_getinfo($ch));
        curl_close($ch);
        return ($this->_http_code = 200) ? true : false;
    }

    public function getLastResponse() {
        return $this->_http_body;
    }

    public function getLastResponseInfo() {
        return $this->_http_info;
    }

    public function getLastRequestHeader() {
        return $this->_http_info["request_header"];
    }

}