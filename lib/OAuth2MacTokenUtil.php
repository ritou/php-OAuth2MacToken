<?php

/**
 * OAuth 2.0 MAC Token Utility Class
 */
class OAuth2MacTokenUtil {

    /**
     * Generate Authorization Request Header String
     * @param string $key_id MAC key identifier
     * @param string $key MAC key
     * @param string $algorithm MAC algorithm
     * @param int $iss Issue time
     * @param string $nonce
     * @param string $method
     * @param string $url
     * @param string $entitybody request payload body
     * @param string $ext "ext" "Authorization" request header field attribute
     * @return string
     */
    public static function genetateAuthZHeader($key_id, $key, $algorithm, $iss, $nonce=null, $method, $url, $entitybody=null, $ext=null) {

        // Check MAC Credentials
        if (empty($key_id) || empty($key) || empty($algorithm) || (empty($nonce) && empty($iss))) {
            throw new Exception('Missing MAC Credentials');
        }

        // Process nonce
        if (empty($nonce)) {
            $nonce = OAuth2Util::generateNonceStr($iss);
        }

        // Check request data
        if (empty($method) || empty($url)) {
            throw new Exception('Missing Params');
        }

        // Process entity-body
        $bodyhash = (!empty($entitybody)) ? self::generateBodyhash($entitybody, $algorithm) : "";
        $mac = self::generateMac($key_id, $key, $algorithm, $iss, $nonce, $method, $url, $bodyhash, $ext);
        return self::_buildAuthZHeaderStr($key_id, $nonce, $bodyhash, $ext, $mac);
    }

    /**
     * Generate MAC String
     * @param string $key_id MAC key identifier
     * @param string $key MAC key
     * @param string $algorithm MAC algorithm
     * @param int $iss Issue time
     * @param string $nonce
     * @param string $method
     * @param string $url
     * @param string $bodyhash request payload body hash
     * @param string $ext "ext" "Authorization" request header field attribute
     * @return string
     */
    public static function generateMac($key_id, $key, $algorithm, $iss, $nonce=null, $method, $url, $bodyhash=null, $ext=null) {

        // Check MAC Credentials
        if (empty($key_id) || empty($key) || empty($algorithm) || (empty($nonce) && empty($iss))) {
            throw new Exception('Missing MAC Credentials');
        }

        // Process nonce
        if (empty($nonce)) {
            $nonce = OAuth2Util::generateNonceStr($iss);
        }

        // Check request data
        if (empty($method) || empty($url)) {
            throw new Exception('Missing Params');
        }

        $host = "";
        $port = "";
        $request_uri = "";
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
            $request_uri = substr($url,strpos($url,$urlinfo['path']));
        }

        $basestr = $nonce . "\n" .
                $method . "\n" .
                $request_uri . "\n" .
                $host . "\n" .
                $port . "\n" .
                $bodyhash . "\n" .
                $ext . "\n";
        return self::_calculateMac($basestr, $key, $algorithm);
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
     * Generate Signature String from Signature Base String
     * @param string $basestr
     * @param string $key
     * @param string $algorithm
     * @return string
     */
    private static function _calculateMac($basestr, $key, $algorithm) {
        $mac = "";
        switch ($algorithm) {
            case 'hmac-sha-1':
                // hmac-sha-1
                $mac = base64_encode(hash_hmac('sha1', $basestr, $key, true));
                break;
            case 'hmac-sha-256':
                // hmac-sha-256
                $mac = base64_encode(hash_hmac('sha256', $basestr, $key, true));
                break;
            // Please add other algorithm to here
            default:
                throw new Exception('Unknown Algorithm');
                //break;
        }
        return $mac;
    }

    /**
     * Generate Authorization Header Request String from Paramaters
     * @param string $key_id
     * @param string $nonce
     * @param string $bodyhash
     * @param string $ext
     * @param string $mac
     * @return string
     */
    private static function _buildAuthZHeaderStr($key_id, $nonce, $bodyhash, $ext, $mac) {
        $header = 'Authorization: MAC id="' . $key_id . '",';
        $header .= 'nonce="' . $nonce . '",';
        If (!empty($bodyhash)) {
            $header .= 'bodyhash="' . $bodyhash . '",';
        }
        If (!empty($ext)) {
            $header .= 'ext="' . $ext . '",';
        }
        $header .= 'mac="' . $mac . '"';
        return $header;
    }

}

class OAuth2Util {

    public static function generateAge($iss, $current = null) {
        if (is_null($current)) {
            $current = time();
        }
        return $current - $iss;
    }

    public static function generateRandStr() {
        $mt = microtime();
        $rand = mt_rand();
        return md5($mt . $rand);
    }

    public static function generateNonceStr($iss, $current = null) {
        return self::generateAge($iss, $current) . ":" . self::generateRandStr();
    }

    /*
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
    */
}
