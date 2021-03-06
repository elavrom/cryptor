<?php declare(strict_types=1);

namespace Cryptor;

use Exception;
use InvalidArgumentException;

class Cryptor
{
    /**
     * The key that will be used for encryption/decryption. MUST BE defined by you !
     */
    private ?string $_encryptionSecret = null;

    /**
     * The key that will be used for HMAC signature. MUST BE defined by you !
     */
    private ?string $_signingSecret = null;

    /**
     * Cipher method to be used for data encryption.
     * Can be overridden but must be a valid openssl cipher method.
     *
     * @see openssl_get_cipher_methods() Lists available cipher methods
     * @see Cryptor::encrypt()
     * @see Cryptor::decrypt()
     */
    private string $_cipherMethod;

    /**
     * Hashing algorithm for HMAC signature
     * @see Cryptor::sign()
     */
    private string $_hashHmacAlgo;

    /**
     * Constructor.
     */
    public function __construct(string $encryptionSecret, string $signingSecret, string $cipherMethod = 'aes-256-cbc', $hashHmacAlgo = 'sha256') {
        $this->_encryptionSecret = $encryptionSecret;
        $this->_signingSecret = $signingSecret;

        $cipherMethod = strtolower($cipherMethod);
        if (!in_array($cipherMethod, openssl_get_cipher_methods(), true)) {
            throw new InvalidArgumentException("'$cipherMethod' is not a valid cipher method.");
        }
        $this->_cipherMethod = $cipherMethod;
        
        $hashHmacAlgo = strtolower($hashHmacAlgo);
        if (!in_array($hashHmacAlgo, hash_hmac_algos(), true)) {
            throw new InvalidArgumentException("'$hashHmacAlgo' is not a valid hmac hash algorithm.");
        }
        $this->_hashHmacAlgo = $hashHmacAlgo;
    }

    /**
     * Generates pseudo-random bytes depending on $method's IV length.
     * @param string|null $cipherMethod [Optional] Cipher Method. Defaults to Cryptor::$_cipherMethod
     * @return string Pseudo-random bytes
     *
     * @throws Exception
     * @see Cryptor::getIVLength
     * @see Cryptor::_cipherMethod
     */
    public function generateIV(?string $cipherMethod = null): string
    {
        return random_bytes($this->getIVLength($cipherMethod ?? $this->_cipherMethod));
    }

    /**
     * @param string|null $cipherMethod [Optional] Cipher Method. Defaults to Cryptor::$_cipherMethod
     * @return int $method's IV length.
     *
     * @see Cryptor::_cipherMethod
     */
    public function getIVLength(?string $cipherMethod = null): int
    {
        return openssl_cipher_iv_length($cipherMethod ?? $this->_cipherMethod);
    }

    /**
     * Encrypts $data with a $secret and a $method.
     *
     * @param mixed $data Data to encrypt
     * @param string|null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_encryptionSecret
     * @param string|null $cipherMethod [Optional] Cipher Method. Defaults to Cryptor::$_cipherMethod
     * @param bool $urlSafe Defines if resulting base64 should be URL safe or not (see RFC : https://datatracker.ietf.org/doc/html/rfc4648#page-7 )
     * @return string Base64 of encrypted data.
     *
     * @throws Exception
     * @see Cryptor::generateIV()
     * @see Cryptor::decrypt()
     */
    public function encrypt($data, ?string $secret = null, ?string $cipherMethod = null, bool $urlSafe = false): ?string
    {
        if (null === $data) {
            return null;
        }

        $secret = $secret ?? $this->_encryptionSecret;
        $cipherMethod = $cipherMethod ?? $this->_cipherMethod;

        // Do not encrypt already encrypted data
        if ($this->isEncrypted($data, $secret, $cipherMethod)) {
            return $data;
        }

        $iv = $this->generateIV($cipherMethod);

        $ciphered = openssl_encrypt($data, $cipherMethod, $secret, OPENSSL_RAW_DATA, $iv);
        return $this->b64_encode($iv . $ciphered, $urlSafe);
    }

    /**
     * Encrypts $ivData with a $secret and a $method
     *
     * @param string|null $ivData Data to decrypt, expecting base64(IV DATA) (The result of this encrypt method).
     * @param string|null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_encryptionSecret
     * @param string|null $cipherMethod [Optional] Cipher Method. Defaults to Cryptor::$_cipherMethod
     * @param bool $check [Optional] Prevents infinite loop with isEncrypted method. Should be set by you.
     * @return bool|string Decrypted data, or false on failure.
     *
     * @see Cryptor::_cipherMethod
     * @see Cryptor::encrypt()
     * @see Cryptor::getIVLength()
     * @see Cryptor::isEncrypted()
     */
    public function decrypt(?string $ivData, ?string $secret = null, ?string $cipherMethod = null, bool $check = true)
    {
        if (null === $ivData) {
            return null;
        }

        $secret = $secret ?? $this->_encryptionSecret;
        $cipherMethod = $cipherMethod ?? $this->_cipherMethod;

        if ($check && !$this->isEncrypted($ivData, $secret, $cipherMethod)) {
            return $ivData;
        }

        $ivData = $this->b64_decode($ivData);
        $iv = substr($ivData, 0, $this->getIVLength($cipherMethod));
        $data = substr($ivData, $this->getIVLength($cipherMethod));

        if (
            false === $data
            || strlen($iv) !== $this->getIVLength($cipherMethod)
        ) {
            return false;
        }

        return openssl_decrypt($data, $cipherMethod, $secret, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Simply check if data is already encrypted. Prevents double encryption.
     * @param string $data Data to check
     * @param string|null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_encryptionSecret
     * @param string|null $cipherMethod [Optional] Cipher Method. Defaults to Cryptor::$_cipherMethod
     * @return bool True if data is encrypted, false otherwise
     */
    public function isEncrypted(string $data, ?string $secret = null, ?string $cipherMethod = null): bool
    {
        return false !== $this->decrypt($data, $secret, $cipherMethod, false);
    }

    /**
     * HMAC Signs data
     * @param string $dataOrFile Data (or file path as the var name says) to sign
     * @param string|null $secret [Optional] Secret to sign data with. Default to Cryptor::$_signingSecret
     * @param string|null $hashHmacAlgo [Optional] Cipher Method. Defaults to Cryptor::$_hashHmacAlgo
     * @return string Data signature
     */
    public function sign(string $dataOrFile, ?string $secret = null, string $hashHmacAlgo = null): string
    {
        $function = is_file($dataOrFile) && is_readable($dataOrFile) ? 'hash_hmac_file' : 'hash_hmac';
        return $function($hashHmacAlgo ?? $this->_hashHmacAlgo, $dataOrFile, $secret ?? $this->_signingSecret);
    }

    /**
     * Checks HMAC signature's validity
     * @param string $signature The signature to check
     * @param string $data The data that has been signed
     * @param string|null $secret [Optional] Secret to sign data with. Default to Cryptor::$_signingSecret
     * @param string|null $hashHmacAlgo [Optional] Cipher Method. Defaults to Cryptor::$_hashHmacAlgo
     * @return bool True if $signature is valid, false otherwise
     */
    public function checkSignature(string $signature, string $data, ?string $secret = null, ?string $hashHmacAlgo = null): bool
    {
        return $signature === $this->sign($data, $secret, $hashHmacAlgo);
    }

    /**
     * @param string $data Data to base64 encode
     * @param bool $urlSafe [Optional] Determines if resulting base64 should be URL safe. Defaults to false
     * @return string Base64 encoded data
     */
    private function b64_encode(string $data, bool $urlSafe = false): string
    {
        $data = base64_encode($data);
        if ($urlSafe) {
            $data = str_replace(['+', '/', '='], ['-', '_', ''], $data);
        }
        return $data;
    }

    /**
     * @param string $data Data to base64 decode. Automatically detects if base64 is URL safe.
     * @return string Decoded data
     */
    private function b64_decode(string $data): string
    {
        if (false !== strpos($data, '-') || false !== strpos($data, '_')) {
            $data = str_replace(['-', '_'], ['+', '/'], $data);
        }
        return base64_decode($data);
    }
}