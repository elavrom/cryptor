# Cryptor
A simple helper class for encryption, decryption, and hmac signing.

---

## Get Started

Cryptor class is a singleton.
In order to use it, you have to call the static method `Cryptor::getInstance()`.

For the first instantiation, you have to provide two secret keys that will be your passphrases.

It is recommended that you generate your own secret keys to encrypt and sign data, and keep it safe.
A way of generating this kind of secret key is to use OpenSSL :
```shell
# Hexadecimal doubles the number of bytes
# so that would be a 64 bytes long passphrase
openssl rand -hex 32
```

## Examples

### Encryption / Decryption

```php
$cryptor = Cryptor::getInstance($_ENV['MY_ENCRYPTION_SECRET'], $_ENV['MY_SIGNING_SECRET']);
$myData = '{"a": "This is a sample value."}';

$encrypted = $cryptor->encrypt($myData);
$decrypted = $cryptor->decrypt($encrypted);

// If you don't want to use default cipher method, or default secret, you can override them :
$encrypted = $cryptor->encrypt($myData, null, 'aes-128-cbc');
$encrypted = $cryptor->decrypt($encrypted, null, 'aes-128-cbc');

$encrypted = $cryptor->encrypt($myData, 'myCustomKey', null);
$encrypted = $cryptor->decrypt($encrypted, 'myCustomKey', null);

// You can get URL safe base64 result with the last argument : 
$encrypted = $cryptor->encrypt($myData, null, null, true);
```

### HMAC Signing / Checking

```php
$cryptor = Cryptor::getInstance($_ENV['MY_ENCRYPTION_SECRET'], $_ENV['MY_SIGNING_SECRET']);
$myData = '{"a": "This is a sample value."}';

// You can simply sign your data with : 
$signature = $cryptor->sign($myData);
// And check if a signature originated from you with :
$valid = $cryptor->checkSignature($signature, $myData);
// You can also sign a file directly. Cryptor checks if the file exists and is readable : 
$signature = $cryptor->sign('/path/to/my/file.txt');

// Same as encryption, you can override the secret and the hash algorithm : 
$signature = $cryptor->sign($myData, 'myCustomSecret', null);
$valid = $cryptor->checkSignature($signature, $myData, 'myCustomSecret', null);

$signature = $cryptor->sign($myData, null, 'sha384');
$valid = $cryptor->checkSignature($signature, $myData, null, 'sha384');
```