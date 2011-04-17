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
                        137131200,
                        'dj83hs9s',
                        'GET',
                        'http://example.com/resource/1?b=1&a=2');
        $this->assertEquals('Authorization: MAC token="h480djs93hd8",timestamp="137131200",nonce="dj83hs9s",signature="YTVjyNSujYs1WsDurFnvFi4JK6o="', $testauthzheader);
        $testauthzheader = OAuth2MacTokenUtil::genetateAuthZHeader('h480djs93hd8',
                        '489dks293j39',
                        'hmac-sha-1',
                        137131200,
                        'dj83hs9s',
                        'POST',
                        'http://example.com/request',
                        'hello=world%21');
        $this->assertEquals('Authorization: MAC token="h480djs93hd8",timestamp="137131200",nonce="dj83hs9s",bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",signature="OQsqDpSwH9fv6E2Iy5xdGhMGyrE="', $testauthzheader);

        $authzheader_array = array();
        $authzheader_array2 = array();
        for ($i = 0; $i < 10000; $i++) {
            $authzheader_array[] = OAuth2MacTokenUtil::genetateAuthZHeader('h480djs93hd8',
                            '489dks293j39',
                            'hmac-sha-1',
                            null,
                            null,
                            'GET',
                            'http://example.com/resource/1?b=1&a=2');

            $authzheader_array2[] = OAuth2MacTokenUtil::genetateAuthZHeader('h480djs93hd8',
                            '489dks293j39',
                            'hmac-sha-1',
                            null,
                            null,
                            'POST',
                            'http://example.com/request',
                            'hello=world%21');
        }
        $this->assertEquals($authzheader_array, array_unique($authzheader_array));
        $this->assertEquals($authzheader_array2, array_unique($authzheader_array2));
    }

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

    public function testGenerateBodyhash() {
        $this->assertEquals('qUqP5cyxm6YcTAhz05Hph5gvu9M=', OAuth2MacTokenUtil::generateBodyhash('test', 'hmac-sha-1'));
        $this->assertEquals('n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=', OAuth2MacTokenUtil::generateBodyhash('test', 'hmac-sha-256'));
        // sample at http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token-02
        $this->assertEquals('k9kbtCIy0CkI3/FEfpS/oIDjk6k=', OAuth2MacTokenUtil::generateBodyhash('hello=world%21', 'hmac-sha-1'));
        $this->assertEquals('Lve95gjOVATpfV8EL5X4nxwjKHE=', OAuth2MacTokenUtil::generateBodyhash('Hello World!', 'hmac-sha-1'));
    }

}