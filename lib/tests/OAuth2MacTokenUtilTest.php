<?php

require_once '../OAuth2MacTokenUtil.php';

/**
 * Test class for OAuth2MacTokenUtil.
 */
class OAuth2MacTokenUtilTest extends PHPUnit_Framework_TestCase {

    public function testGenetateAuthZHeader() {
        // sample at http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token-02
        $testauthzheader = OAuth2MacTokenUtil::genetateAuthZHeader('h480djs93hd8',
                        '489dks293j39',
                        'hmac-sha-1',
                        strtotime("Thu, 02 Dec 2010 21:39:45 GMT"),
                        '264095:dj83hs9s',
                        'GET',
                        'http://example.com:80/resource/1?b=1&a=2');
        $this->assertEquals('Authorization: MAC id="h480djs93hd8",nonce="264095:dj83hs9s",mac="SLDJd4mg43cjQfElUs3Qub4L6xE="', $testauthzheader);

        $testauthzheader = OAuth2MacTokenUtil::genetateAuthZHeader('jd93dh9dh39D',
                        '8yfrufh348h',
                        'hmac-sha-1',
                        strtotime("Thu, 02 Dec 2010 21:39:45 GMT"),
                        '273156:di3hvdf8',
                        'POST',
                        'http://example.com:80/request',
                        'hello=world%21');
        $this->assertEquals('Authorization: MAC id="jd93dh9dh39D",nonce="273156:di3hvdf8",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",mac="W7bdMZbv9UWOTadASIQHagZyirA="', $testauthzheader);

        $authzheader_array = array();
        $authzheader_array2 = array();
        for ($i = 0; $i < 10000; $i++) {
        $authzheader_array[] = OAuth2MacTokenUtil::genetateAuthZHeader('h480djs93hd8',
                        '489dks293j39',
                        'hmac-sha-1',
                        strtotime("Thu, 02 Dec 2010 21:39:45 GMT"),
                        '',
                        'GET',
                        'http://example.com:80/resource/1?b=1&a=2');

        $authzheader_array2[] = OAuth2MacTokenUtil::genetateAuthZHeader('jd93dh9dh39D',
                        '8yfrufh348h',
                        'hmac-sha-1',
                        strtotime("Thu, 02 Dec 2010 21:39:45 GMT"),
                        '',
                        'POST',
                        'http://example.com:80/request',
                        'hello=world%21');
        }
        $this->assertEquals($authzheader_array, array_unique($authzheader_array));
        $this->assertEquals($authzheader_array2, array_unique($authzheader_array2));
    }

    /*
    public function testGenerateSignature() {
        // sample at http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token-02
        $testsig = OAuth2MacTokenUtil::generateSignature('h480djs93hd8',
                        '489dks293j39',
                        'hmac-sha-1',
                        137131200,
                        'dj83hs9s',
                        'GET',
                        'http://example.com/resource/1?b=1&a=2');
        $this->assertEquals('YTVjyNSujYs1WsDurFnvFi4JK6o=', $testsig);
        $testsig = OAuth2MacTokenUtil::generateSignature('h480djs93hd8',
                        '489dks293j39',
                        'hmac-sha-1',
                        137131200,
                        'dj83hs9s',
                        'POST',
                        'http://example.com/request',
                        'hello=world%21');
        $this->assertEquals('OQsqDpSwH9fv6E2Iy5xdGhMGyrE=', $testsig);

        $sig_array = array();
        $sig_array2 = array();
        for ($i = 0; $i < 10000; $i++) {
            $sig_array[] = OAuth2MacTokenUtil::generateSignature('h480djs93hd8',
                            '489dks293j39',
                            'hmac-sha-1',
                            null,
                            null,
                            'GET',
                            'http://example.com/resource/1?b=1&a=2');

            $sig_array2[] = OAuth2MacTokenUtil::generateSignature('h480djs93hd8',
                            '489dks293j39',
                            'hmac-sha-1',
                            null,
                            null,
                            'POST',
                            'http://example.com/request',
                            'hello=world%21');
        }
        $this->assertEquals($sig_array, array_unique($sig_array));
        $this->assertEquals($sig_array2, array_unique($sig_array2));
    }
    */

    public function testGenerateBodyhash() {
        $this->assertEquals('qUqP5cyxm6YcTAhz05Hph5gvu9M=', OAuth2MacTokenUtil::generateBodyhash('test', 'hmac-sha-1'));
        $this->assertEquals('n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=', OAuth2MacTokenUtil::generateBodyhash('test', 'hmac-sha-256'));
        // sample at http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token-02
        $this->assertEquals('k9kbtCIy0CkI3/FEfpS/oIDjk6k=', OAuth2MacTokenUtil::generateBodyhash('hello=world%21', 'hmac-sha-1'));
        $this->assertEquals('Lve95gjOVATpfV8EL5X4nxwjKHE=', OAuth2MacTokenUtil::generateBodyhash('Hello World!', 'hmac-sha-1'));
    }

}