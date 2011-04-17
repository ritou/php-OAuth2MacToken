<?php

include_once("lib/OAuth2MacTokenUtil.php");

/**
 * OAuth 2.0 MAC Token Resource Server Class
 */
class OAuth2MacTokenServer {

    private $_headers = array();
    private $_enabled = true;
    private $_token = null;
    private $_secret = null;
    private $_algorithm = null;
    private $_timestamp = null;
    private $_nonce = null;
    private $_bodyhash = null;
    private $_signature = null;
    private $_method = null;
    private $_url = null;
    private $_entitybody = null;
    private $_error = null;
    private $_realm = null;
    private $_code = null;

    public function __construct() {
        $this->_realm = self::getRequestHost();
        $this->_headers = apache_request_headers();
        $this->_method = self::getRequestMethod();
        $this->_url = self::getRequestUrl();
        $this->_entitybody = self::getEntityBody();
        $this->parseAuthZHeader();
        
        if ($this->_enabled) {
            if (empty($this->_token)) {
                $this->_enabled = false;
                $this->_code = 'HTTP/1.1 400 Bad Request';
                $this->_error = 'missing_token';
            }
            if (empty($this->_timestamp)) {
                $this->_enabled = false;
                $this->_code = 'HTTP/1.1 400 Bad Request';
                $this->_error = 'missing_timestamp';
            }
            if (empty($this->_nonce)) {
                $this->_enabled = false;
                $this->_code = 'HTTP/1.1 400 Bad Request';
                $this->_error = 'missing_nonce';
            }
            if (!empty($this->_entitybody) && empty($this->_bodyhash)) {
                $this->_enabled = false;
                $this->_code = 'HTTP/1.1 400 Bad Request';
                $this->_error = 'missing_bodyhash';
            }
            if (empty($this->_signature)) {
                $this->_enabled = false;
                $this->_code = 'HTTP/1.1 400 Bad Request';
                $this->_error = 'missing_signature';
            }
        }
    }

    public function getStatus() {
        return $this->_enabled;
    }

    public function getToken() {
        return $this->_token;
    }

    public function getTimestamp() {
        return $this->_timestamp;
    }

    public function getNonce() {
        return $this->_nonce;
    }

    public function getBodyHash() {
        return $this->_bodyhash;
    }

    public function getMethod() {
        return $this->_method;
    }

    public function setSecret($secret) {
        $this->_secret = $secret;
    }

    public function setAlgorithm($algorithm) {
        $this->_algorithm = $algorithm;
    }

    public function setHttpResponseError($error) {
        $this->_error = $error;
    }

    public function setHttpResponseRealm($realm) {
        $this->_realm = $realm;
    }

    public function setHttpResponseCode($code) {
        $this->_code = $code;
    }

    public function getHttpResponseCode() {
        return $this->_code;
    }

    /**
     * Return AuthN response header string
     * @return string
     */
    public function getHttpResponseAuthNHeader() {
        $str = 'WWW-Authenticate: MAC realm="' . $this->_realm . '"';
        if (!empty($this->_error)) {
            $str .= ',error="' . $this->_error . '"';
        }
        return $str;
    }

    /**
     * Parse AuthZ Header and set params
     */
    private function parseAuthZHeader() {
        $authZstr = self::getAuthZHeader($this->_headers);
        if (empty($authZstr) || substr($authZstr, 0, 4) != 'MAC ') {
            $this->_enabled = false;
            $this->_code = 'HTTP/1.1 400 Bad Request';
            $this->_error = 'invalid_authorizationheader';
            return;
        }
        $authZstr = substr($authZstr, 4);
        $params = explode(',', $authZstr);
        foreach ($params as $param) {
            $key = substr($param, 0, strpos($param, '='));
            $value = trim(substr($param, strpos($param, '=') + 1), '"');
            $authZparams[$key] = $value;
        }
        $this->_token = $authZparams['token'];
        $this->_timestamp = (int) $authZparams['timestamp'];
        $this->_nonce = $authZparams['nonce'];
        $this->_bodyhash = $authZparams['bodyhash'];
        $this->_signature = $authZparams['signature'];
    }

    /**
     * Validate bodyhash param
     */
    public function validateBodyHash() {
        if (empty($this->_algorithm)) {
            throw new Exception('Missing Algorithm');
        }
        if (!empty($this->_entitybody)) {
            $cal_bodyhash = OAuth2MacTokenUtil::generateBodyhash($this->_entitybody, $this->_algorithm);
            if ($this->_bodyhash != $cal_bodyhash) {
                $this->_enabled = false;
                $this->_code = 'HTTP/1.1 401 Unauthorized';
                $this->_error = 'invalid_bodyhash';
            }
        }
    }

    /**
     * Validate signature param
     */
    public function validateSignature() {
        if (empty($this->_secret) || empty($this->_algorithm)) {
            throw new Exception('Missing MAC Credential(secret/algorithm)');
        }
        $cal_signature = OAuth2MacTokenUtil::generateSignature($this->_token, $this->_secret, $this->_algorithm, $this->_timestamp, $this->_nonce, $this->_method, $this->_url, $this->_entitybody);
        if ($this->_signature != $cal_signature) {
            $this->_enabled = false;
            $this->_code = 'HTTP/1.1 401 Unauthorized';
            $this->_error = 'invalid_signature';
        }
    }

    /**
     * Validate timestamp param
     * @param string $validsec
     */
    public function validateTimestamp($validsec) {
        if (($this->_timestamp > OAuth2Util::generateTimestamp() + (int) $validsec) ||
                ($this->_timestamp < OAuth2Util::generateTimestamp() - (int) $validsec)) {
            $this->_enabled = false;
            $this->_code = 'HTTP/1.1 400 Bad Request';
            $this->_error = 'invalid_timestamp';
        }
    }

    /*
     * Utility funcs
     */
    public static function getRequestHost() {
        return $_SERVER["HTTP_HOST"];
    }

    public static function getRequestMethod() {
        return $_SERVER["REQUEST_METHOD"];
    }

    public static function getRequestUrl() {
        if ($_SERVER["SERVER_PORT"] == '443') {
            $url = 'https://';
        } else {
            $url = 'http://';
        }
        $url .= $_SERVER["HTTP_HOST"] . ':' . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
        return $url;
    }

    public static function getStandardGetparameters() {
        return $_GET;
    }

    public static function getAuthZHeader($headers) {
        return $headers["Authorization"];
    }

    public static function getContentType($headers) {
        return $headers["Content-Type"];
    }

    public static function getEntityBody() {
        return @file_get_contents('php://input');
    }

}