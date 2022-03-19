<?php declare(strict_types=1);

namespace Cryptor\Tests;

use Cryptor\Cryptor;
use Exception;
use PHPUnit\Framework\TestCase;

class CryptorTest extends TestCase
{
    public const TEST_ENCRYPTION_SECRET = 'secret123';
    public const TEST_SIGNING_SECRET = 'secret123';
    public const TEST_CIPHER_METHOD = 'aes-256-cbc';
    public const TEST_HASH_HMAC_ALGO = 'sha256';

    private static Cryptor $cryptor;

    public static function setUpBeforeClass(): void
    {
        self::$cryptor = Cryptor::getInstance(
            self::TEST_ENCRYPTION_SECRET,
            self::TEST_SIGNING_SECRET,
            self::TEST_CIPHER_METHOD,
            self::TEST_HASH_HMAC_ALGO
        );
    }

    public function testGetIVSize(): void
    {
        $this->assertEquals(16, self::$cryptor->getIVLength());
    }

    /**
     * @throws Exception
     */
    public function testGenerateIV(): void
    {
        // Only assert length since IV is pseudo-random
        $iv = self::$cryptor->generateIV();
        $this->assertEquals(16, strlen($iv));
        $iv = self::$cryptor->generateIV(self::TEST_CIPHER_METHOD);
        $this->assertEquals(16, strlen($iv));
    }

    /**
     * @throws Exception
     */
    public function testIsEncrypted(): void
    {
        $str = 'Hello ! I\'m a string!';

        $encrypted = self::$cryptor->encrypt($str);
        $decrypted = self::$cryptor->decrypt($encrypted);

        $this->assertTrue(self::$cryptor->isEncrypted($encrypted));
        $this->assertFalse(self::$cryptor->isEncrypted($decrypted));
    }

    /**
     * @throws Exception
     */
    public function testEncryptAndDecrypt(): void
    {
        $str = 'Hello ! I\'m a string!';

        $encrypted = self::$cryptor->encrypt($str);
        $decrypted = self::$cryptor->decrypt($encrypted);

        $this->assertEquals($str, $decrypted);
        $this->assertNotEquals($str, $encrypted);
        $this->assertNotEquals($str, self::$cryptor->decrypt($encrypted, 'wrongsecret'));
    }

    /**
     * @throws Exception
     */
    public function testEncryptAndDecryptUrlSafe(): void
    {
        $str = 'Hello ! I\'m a string!';

        $encrypted = self::$cryptor->encrypt($str, null, null, true);
        $decrypted = self::$cryptor->decrypt($encrypted);

        $this->assertFalse(strpos($encrypted, '+'));
        $this->assertFalse(strpos($encrypted, '/'));
        $this->assertEquals($str, $decrypted);
        $this->assertNotEquals($str, $encrypted);
        $this->assertNotEquals($str, self::$cryptor->decrypt($encrypted, 'wrongsecret'));
    }

    public function testHashHmacSignature(): void
    {
        $this->assertEquals('167580a537bfcb06f43358f8422ac08ecfb520d67b9ea699b053b9499e102340', self::$cryptor->sign('Hello ! I\'m a string!'));
        $this->assertEquals('3819c21c2e24d2974c44e79de6dbe6e31367a67df90840973a31950484b69700', self::$cryptor->sign(dirname(__FILE__, 4) . '/LICENSE'));
    }

    public function testCheckSignature(): void
    {
        $this->assertTrue(self::$cryptor->checkSignature('167580a537bfcb06f43358f8422ac08ecfb520d67b9ea699b053b9499e102340', 'Hello ! I\'m a string!'));
        $this->assertTrue(self::$cryptor->checkSignature('3819c21c2e24d2974c44e79de6dbe6e31367a67df90840973a31950484b69700', dirname(__FILE__, 4) . '/LICENSE'));
    }

}