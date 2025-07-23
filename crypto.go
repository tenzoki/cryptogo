package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

func getKey() ([]byte, error) {
	keyHex := os.Getenv("MKEY")
	if keyHex == "" {
		keyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, errors.New("MKEY must be 64 hex chars (32 bytes)")
	}
	return key, nil
}

func Encrypt(data []byte) ([]byte, error) {
	key, err := getKey()
	if err != nil {
		return nil, err
	}
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

func Decrypt(enc []byte) ([]byte, error) {
	key, err := getKey()
	if err != nil {
		return nil, err
	}
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
