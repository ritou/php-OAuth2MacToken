<?php

/**
 * OAuth 2.0 MAC Token Utility Class
 */
class OAuth2MacTokenUtil {

    /**
     * Generate Authorization Request Header String
     * @param string $token
     * @param string $secret
     * @param string $algorithm
     * @param int $timestamp
     * @param string $nonce
     * @param string $method
     * @param string $url
     * @param string $entitybody
     * @return string
     */
    public static function genetateAuthZHeader($token, $secret, $algorithm, $timestamp=null, $nonce=null, $method, $url, $entitybody=null) {

        // Check required params
        if (empty($token) || empty($secret) || empty($algorithm) || empty($method) || empty($url)) {
            throw new Exception('Missing Params');
        }

        // Process timestamp
        if (empty($timestamp)) {
            $timestamp = OAuth2Util::generateTimestamp();
        } else {
            // ToDo : check valid timestamp
            if (!is_numeric($timestamp)) {
                throw new Exception('Invalid Timestamp');
            }
        }

        // Process nonce
        if (empty($nonce)) {
            $nonce = OAuth2Util::generateNonce();
        }

        // Process entity-body
        $bodyhash = (!empty($entitybody)) ? self::generateBodyhash($entitybody, $algorithm) : "";
        $signature = self::generateSignature($token, $secret, $algorithm, $timestamp, $nonce, $method, $url, $entitybody);
        return self::_generateAuthZHeaderStr($token, $timestamp, $nonce, $bodyhash, $signature);
    }

    /**
     * Generate Signature String
     * @param string $token
     * @param string $secret
     * @param string $algorithm
     * @param int $timestamp
     * @param string $nonce
     * @param string $method
     * @param string $url
     * @param string $entitybody
     * @return string
     */
    public static function generateSignature($token, $secret, $algorithm, $timestamp, $nonce, $method, $url, $entitybody=null) {

        // Check required params
        if (empty($token) || empty($secret) || empty($algorithm) || empty($method) || empty($url)) {
            throw new Exception('Missing Params');
        }

        // Process timestamp
        if (empty($timestamp)) {
            $timestamp = OAuth2Util::generateTimestamp();
        } else {
            // ToDo : check valid timestamp
            if (!is_numeric($timestamp)) {
                throw new Exception('Invalid Timestamp');
            }
        }

        // Process nonce
        if (empty($nonce)) {
            $nonce = OAuth2Util::generateNonce();
        }

        // Process entity-body
        $bodyhash = (!empty($entitybody)) ? self::generateBodyhash($entitybody, $algorithm) : "";

        $host = "";
        $port = "";
        $path = "";
        $host = "";
        $params = array();
        $urlinfo = parse_url($url);

        if (!$urlinfo) {
            throw new Exception('Invalid URL');
        } else {
            if ($urlinfo['scheme'] != 'https' && $urlinfo['scheme'] != 'http') {
                throw new Exception('Invalid URL Scheme');
            }
            $host = $urlinfo['host'];
            if (isset($urlinfo['port']) && !empty($urlinfo['port'])) {
                $port = $urlinfo['port'];
            } else {
                if ($urlinfo['scheme'] == 'https') {
                    $port = '443';
                } else if ($urlinfo['scheme'] == 'http') {
                    $port = '80';
                }
            }
            $path = $urlinfo['path'];
            parse_str($urlinfo['query'], $params);
        }

        $basestr = $token . "\n" .
                $timestamp . "\n" .
                $nonce . "\n" .
                $bodyhash . "\n" .
                $method . "\n" .
                $host . "\n" .
                $port . "\n" .
                $path . "\n" .
                self::_generateNormalizedParamString($params);
        return self::_buildSignature($basestr, $secret, $algorithm);
    }

    /**
     * Generate Request Body Hash String
     * @param string $entitybody
     * @param string $algorithm
     * @return string
     */
    public static function generateBodyhash($entitybody, $algorithm) {
        $bodyhash = "";
        switch ($algorithm) {
            case 'hmac-sha-1':
                $bodyhash = base64_encode(hash('sha1', $entitybody, true));
                break;
            case 'hmac-sha-256':
                $bodyhash = base64_encode(hash('sha256', $entitybody, true));
                break;
            // Please add other algorithm to here
            default:
                throw new Exception('Unknown Algorithm');
            //break;
        }
        return $bodyhash;
    }

    /**
     * Generate Normalized Parameter String
     * @param array $params
     * @return string
     */
    private static function _generateNormalizedParamString($params) {
        if (!empty($params)) {
            $keys = array_map(array('OAuth2Util', 'urlencodeRFC3986'), array_keys($params));
            $values = array_map(array('OAuth2Util', 'urlencodeRFC3986'), array_values($params));
            $enc_params = array_combine($keys, $values);
            uksort($enc_params, 'strnatcmp');
            $paramstr = null;
            foreach ($enc_params as $key => $value) {
                $paramstr .= $key . "=" . $value . "\n";
            }
        } else {
            $paramstr = "\n";
        }
        return $paramstr;
    }

    /**
     * Generate Signature String from Signature Base String
     * @param string $basestr
     * @param string $secret
     * @param string $algorithm
     * @return string
     */
    private static function _buildSignature($basestr, $secret, $algorithm) {
        $signature = "";
        switch ($algorithm) {
            case 'hmac-sha-1':
                // hmac-sha-1
                $signature = base64_encode(hash_hmac('sha1', $basestr, $secret, true));
                break;
            case 'hmac-sha-256':
                // hmac-sha-256
                $signature = base64_encode(hash_hmac('sha256', $basestr, $secret, true));
                break;
            // Please add other algorithm to here
            default:
                throw new Exception('Unknown Algorithm');
            //break;
        }
        return $signature;
    }

    /**
     * Generate Authorization Header Request String from Paramaters
     * @param string $token
     * @param int $timestamp
     * @param string $nonce
     * @param string $bodyhash
     * @param string $signature
     * @return string
     */
    private static function _generateAuthZHeaderStr($token, $timestamp, $nonce, $bodyhash, $signature) {
        $header = 'Authorization: MAC token="' . $token . '",';
        $header .= 'timestamp="' . $timestamp . '",';
        $header .= 'nonce="' . $nonce . '",';
        If (!empty($bodyhash)) {
            $header .= 'bodyhash="' . $bodyhash . '",';
        }
        $header .= 'signature="' . $signature . '"';
        return $header;
    }

}

class OAuth2Util {

    public static function generateTimestamp() {
        return time();
    }

    public static function generateNonce() {
        $mt = microtime();
        $rand = mt_rand();
        return md5($mt . $rand);
    }

    public static function urlencodeRFC3986($string) {
        if (is_string($string)) {
            return str_replace('%7E', '~', rawurlencode($string));
        } else {
            return "";
        }
    }

    public static function urldecodeRFC3986($string) {
        if (is_string($string)) {
            return rawurldecode($string);
        } else {
            return "";
        }
    }

}
