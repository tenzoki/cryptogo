# cryptogo

Encrypts and decrypts an `[]byte` with a 32 byte hex key.
Symmetric encryption, shared key.

Up to v1.0.3: key is read from env var `MKEY`

From v1.0.4 onwards:
- `key` is second arg of `Encrypt` and `Decrypt`.
- helper method `GetDecodedKeyFromEnv(envar string) ([]byte)` tries reading key from given env var and decodes the 32 byte string to a byte [].
_ helper method `DecodeHey(keyHex string) []byte` decodes the 32 byte string to a byte []. When `keyHex` len is > 0 and < 32, the function will fill up the missing chars with `0`.


## Main functions:

`func Encrypt(data []byte, key []byte) ([]byte, error)`

`func Decrypt(enc []byte, key []byte) ([]byte, error)`



## License

This project is licensed under the [European Union Public Licence v1.2 (EUPL)](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12).