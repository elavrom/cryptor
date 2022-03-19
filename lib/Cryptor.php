<?php

namespace Elavrom\Cryptor;

class Cryptor
{
    private static ?self $_instance = null;

    /**
     * The key that will be used for both encryption/decryption and HMAC signature. MUST BE defined by you !
     *
     * @see Cryptor::getInstance()
     */
    private static ?string $_key = null;

    /**
     * Cipher method to be used for data encryption.
     * Can be overriden but must be a valid openssl cipher method.
     *
     * @see openssl_get_cipher_methods() pour lister les méthodes disponibles.
     * @see Cryptor::encrypt()
     * @see Cryptor::decrypt()
     */
    private static string $_method;

    /**
     * Hashing algorithm for HMAC signature
     * @see Cryptor::sign()
     */
    private static string $_hashHmacAlgo;

    private function __construct() {
    }

    public static function getInstance(string $key, string $method = 'AES-256-CBC', string $hashHmacAlgo = 'sha256'): self
    {
        if (null === self::$_instance) {
            self::$_instance = new self();
        }

        if (!in_array($method, openssl_get_cipher_methods(), true)) {
            throw new \InvalidArgumentException("'$method' is not a valid cipher method.");
        }

        if (!in_array($hashHmacAlgo, hash_hmac_algos(), true)) {
            throw new \InvalidArgumentException("'$hashHmacAlgo' is not a valid hmac hash algorithm.");
        }

        self::$_key = $key;
        self::$_method = $method;
        self::$_hashHmacAlgo = $hashHmacAlgo;

        return self::$_instance;
    }

    /**
     * Generates pseudo-random bytes depending on $method's IV length.
     * @param string|null $method [Optional] Cipher Method. Defaults to Cryptor::$_method
     * @return string Pseudo-random bytes
     *
     * @throws \Exception
     * @see Cryptor::getIVLength
     * @see Cryptor::_method
     */
    public function generateIV(?string $method = null): string
    {
        return random_bytes($this->getIVLength($method ?? self::$_method));
    }

    /**
     * @param string|null $method [Optional] Cipher Method. Defaults to Cryptor::$_method
     * @return int $method's IV length.
     *
     * @see Cryptor::_method
     */
    public function getIVLength(?string $method = null): int
    {
        return openssl_cipher_iv_length($method ?? self::$_method);
    }

    /**
     * Encrypts $data with a $secret and a $method.
     *
     * @param mixed $data Data to encrypt
     * @param null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_key
     * @param string|null $method [Optional] Cipher Method. Defaults to Cryptor::$_method
     * @param bool $urlSafe Defines if resulting base64 should be URL safe or not (see RFC : https://datatracker.ietf.org/doc/html/rfc4648#page-7 )
     * @return string Base64 of encrypted data.
     *
     * @throws \Exception
     * @see Cryptor::generateIV()
     * @see Cryptor::decrypt()
     */
    public function encrypt(mixed $data, $secret = null, ?string $method = null, bool $urlSafe = false): string
    {
        $secret = $secret ?? self::$_key;
        $method = $method ?? self::$_method;

        // Do not encrypt already encrypted data
        if ($this->isEncrypted($data, $secret, $method)) {
            return $data;
        }

        $iv = $this->generateIV($method);

        $ciphered = openssl_encrypt($data, $method, $secret, OPENSSL_RAW_DATA, $iv);
        return $this->b64_encode($iv . $ciphered, $urlSafe);
    }

    /**
     * Encrypts $ivData with a $secret and a $method
     *
     * @param string $ivData Data to decrypt, expecting base64(IVDATA) (The result of this encrypt method).
     * @param null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_key
     * @param string|null $method [Optional] Cipher Method. Defaults to Cryptor::$_method
     * @param bool $check [Optional] Prevents infinite loop with isEncrypted method. Should be set by you.
     * @return bool|string Decrypted data, or false on failure.
     *
     * @see Cryptor::_method
     * @see Cryptor::encrypt()
     * @see Cryptor::getIVLength()
     * @see Cryptor::isEncrypted()
     */
    public function decrypt(string $ivData, $secret = null, ?string $method = null, bool $check = true): bool|string
    {
        $secret = $secret ?? self::$_key;
        $method = $method ?? self::$_method;

        if ($check && !$this->isEncrypted($ivData, $secret, $method)) {
            return $ivData;
        }

        $ivData = $this->b64_decode($ivData);
        $iv = substr($ivData, 0, $this->getIVLength($method));
        $data = substr($ivData, $this->getIVLength($method));

        if (
            false === $data
            || strlen($iv) !== $this->getIVLength($method)
        ) {
            return false;
        }

        return openssl_decrypt($data, $method, $secret, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Simply check if data is already encrypted. Prevents double encryption.
     * @param string $data Data to check
     * @param string|null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_key
     * @param string|null $method [Optional] Cipher Method. Defaults to Cryptor::$_method
     * @return bool True if data is encrypted, false otherwise
     */
    public function isEncrypted(string $data, ?string $secret = null, ?string $method = null): bool
    {
        return false !== $this->decrypt($data, $secret, $method, false);
    }

    /**
     * HMAC Signs data
     * @param string $data Data to sign
     * @param string|null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_key
     * @param string|null $hashHmacAlgo [Optional] Cipher Method. Defaults to Cryptor::$_hashHmacAlgo
     * @return string Data signature
     */
    public function sign(string $data, ?string $secret = null, string $hashHmacAlgo = null): string
    {
        return hash_hmac($hashHmacAlgo ?? self::$_hashHmacAlgo, $data, $secret ?? self::$_key);
    }

    /**
     * Checks HMAC signature's validity
     * @param string $signature The signature to check
     * @param string $data The data that has been signed
     * @param string|null $secret [Optional] Secret to symmetrically encrypt data with. Default to Cryptor::$_key
     * @param string|null $method [Optional] Cipher Method. Defaults to Cryptor::$_hashHmacAlgo
     * @return bool True if $signature is valid, false otherwise
     */
    public function checkSignature(string $signature, string $data, ?string $secret = null, ?string $method = null): bool
    {
        return $signature === $this->sign($data, $secret, $method ?? self::$_hashHmacAlgo);
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
        if (str_contains($data, '-') || str_contains($data, '_')) {
            $data = str_replace(['-', '_'], ['+', '/'], $data);
        }
        return base64_decode($data);
    }
}