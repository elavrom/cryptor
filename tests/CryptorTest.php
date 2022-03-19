<?php declare(strict_types=1);

namespace Elavrom\Cryptor\Tests;

use Elavrom\Cryptor\Cryptor;
use PHPUnit\Framework\TestCase;

class CryptorTest extends TestCase
{
    public const TEST_KEY = 'secret123';
    public const TEST_METHOD = 'AES-256-CBC';
    public const TEST_HASH_HMAC_ALHO = 'sha256';

    public function testGetIVSize(): void
    {
        $cryptor = Cryptor::getInstance(self::TEST_KEY);
        $this->assertEquals(16, $cryptor->getIVLength(self::TEST_METHOD));
    }

    public function testGenerateIV(): void
    {
        // Only assert length since IV is pseudo-random
        $cryptor = Cryptor::getInstance(self::TEST_KEY);
        $iv = $cryptor->generateIV();
        $this->assertEquals(16, strlen($iv));
        $iv = $cryptor->generateIV(self::TEST_METHOD);
        $this->assertEquals(16, strlen($iv));
    }

    public function testEncryptAndDecrypt(): void
    {
        $cryptor = Cryptor::getInstance(self::TEST_KEY);
        $str = 'Hello ! I\'m a string!';

        $encrypted = $cryptor->encrypt($str, self::TEST_KEY, self::TEST_METHOD);
        $decrypted = $cryptor->decrypt($encrypted, self::TEST_KEY);

        $this->assertEquals($str, $decrypted);
        $this->assertNotEquals($str, $encrypted);
        $this->assertNotEquals($str, $cryptor->decrypt($encrypted, 'wrongsecret'));
    }

    public function testEncryptAndDecryptUrlSafe(): void
    {
        $cryptor = Cryptor::getInstance(self::TEST_KEY);
        $str = 'Hello ! I\'m a string!';

        $encrypted = $cryptor->encrypt($str, self::TEST_KEY, self::TEST_METHOD, true);
        $decrypted = $cryptor->decrypt($encrypted, self::TEST_KEY);

        $this->assertFalse(str_contains($encrypted, '+'));
        $this->assertFalse(str_contains($encrypted, '/'));
        $this->assertEquals($str, $decrypted);
        $this->assertNotEquals($str, $encrypted);
        $this->assertNotEquals($str, $cryptor->decrypt($encrypted, 'wrongsecret'));
    }

    public function testHashHmacSignature(): void
    {
        $cryptor = Cryptor::getInstance(self::TEST_KEY);
        $str = 'Hello ! I\'m a string!';

        $this->assertEquals('167580a537bfcb06f43358f8422ac08ecfb520d67b9ea699b053b9499e102340', $cryptor->sign($str));
    }

    public function testCheckSignature(): void
    {
        $cryptor = Cryptor::getInstance(self::TEST_KEY);
        $str = 'Hello ! I\'m a string!';

        $this->assertTrue($cryptor->checkSignature('167580a537bfcb06f43358f8422ac08ecfb520d67b9ea699b053b9499e102340', $str));
    }

}