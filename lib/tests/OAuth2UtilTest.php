<?php

require_once '../OAuth2MacTokenUtil.php';

/**
 * Test class for OAuth2Util.
 */
class OAuth2UtilTest extends PHPUnit_Framework_TestCase {

    public function testGenerateAge() {
        for ($i = 0; $i < 10000; $i++) {
            $ts = OAuth2Util::generateAge(time() - 1);
            $this->assertTrue(is_int($ts));
            $this->assertGreaterThanOrEqual(1, $ts);
            $this->assertGreaterThanOrEqual($ts, 2);
        }
    }

    public function testGenerateRandStr() {
        $rand_array = array();
        for ($i = 0; $i < 10000; $i++) {
            $rand_array[] = OAuth2Util::generateRandStr();
            $this->assertNotNull($rand_array[$i]);
            $this->assertEquals(strlen($rand_array[$i]), 32);
        }
        $this->assertEquals($rand_array, array_unique($rand_array));
    }

    public function testGenerateNonceStr() {
        $nonce_array = array();
        for ($i = 0; $i < 10000; $i++) {
            $nonce_array[] = OAuth2Util::generateNonceStr(time() - 10);
            $this->assertNotNull($nonce_array[$i]);
            $this->assertEquals(strlen($nonce_array[$i]), 35);
        }
        $this->assertEquals($nonce_array, array_unique($nonce_array));
    }

    /*
    public function testUrlencodeRFC3986() {
        $this->assertEquals('abcABC123', OAuth2Util::urlencodeRFC3986('abcABC123'));
        $this->assertEquals('-._~', OAuth2Util::urlencodeRFC3986('-._~'));
        $this->assertEquals('%25', OAuth2Util::urlencodeRFC3986('%'));
        $this->assertEquals('%2B', OAuth2Util::urlencodeRFC3986('+'));
        $this->assertEquals('%0A', OAuth2Util::urlencodeRFC3986("\n"));
        $this->assertEquals('%20', OAuth2Util::urlencodeRFC3986(' '));
        $this->assertEquals('%7F', OAuth2Util::urlencodeRFC3986("\x7F"));
        $this->assertEquals('', OAuth2Util::urlencodeRFC3986(NULL));
        $this->assertEquals('', OAuth2Util::urlencodeRFC3986(new stdClass()));
    }

    public function testUrldecodeRFC3986() {
        $this->assertEquals('abcABC123', OAuth2Util::urldecodeRFC3986('abcABC123'));
        $this->assertEquals('-._~', OAuth2Util::urldecodeRFC3986('-._~'));
        $this->assertEquals('%', OAuth2Util::urldecodeRFC3986('%25'));
        $this->assertEquals('+', OAuth2Util::urldecodeRFC3986('%2B'));
        $this->assertEquals("\n", OAuth2Util::urldecodeRFC3986('%0A'));
        $this->assertEquals(' ', OAuth2Util::urldecodeRFC3986('%20'));
        $this->assertEquals("\x7F", OAuth2Util::urldecodeRFC3986('%7F'));
    }
    */
}
