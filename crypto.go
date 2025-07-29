package crypto


import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func GetDecodedKeyFromEnv(envar string) []byte {
	keyHex := os.Getenv(envar)
	if keyHex == "" {
		fmt.Printf("Env var not set: %s\n", envar)
		return nil
	}
	return DecodeKey(keyHex)
}
func DecodeKey(keyHex string) []byte {
	if len(keyHex) > 0 && len(keyHex) < 64 {
		keyHex = keyHex + strings.Repeat("0", 64-len(keyHex))
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		fmt.Printf("Key must be 64 hex chars (32 bytes)\n")
		return nil
	}
	return key
}

func Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func Decrypt(enc []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(enc) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := enc[:gcm.NonceSize()]
	ciphertext := enc[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
