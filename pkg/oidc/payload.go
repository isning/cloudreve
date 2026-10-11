package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type payloadCodec struct{ aead cipher.AEAD }

func newPayloadCodec(key []byte) *payloadCodec {
	if len(key) == 0 {
		return &payloadCodec{}
	}
	sum := sha256.Sum256(append([]byte("cloudreve:oidc:payload:v1:"), key...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &payloadCodec{aead}
}
func (c *payloadCodec) seal(purpose string, value any) ([]byte, error) {
	if c.aead == nil {
		return nil, fmt.Errorf("external authentication encryption key is unavailable")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return append([]byte{1}, c.aead.Seal(nonce, nonce, data, []byte(purpose))...), nil
}
func (c *payloadCodec) open(purpose string, data []byte, value any) error {
	if c.aead == nil {
		return fmt.Errorf("external authentication encryption key is unavailable")
	}
	n := c.aead.NonceSize()
	if len(data) < 1+n+c.aead.Overhead() || data[0] != 1 {
		return fmt.Errorf("invalid authentication material")
	}
	plain, err := c.aead.Open(nil, data[1:1+n], data[1+n:], []byte(purpose))
	if err != nil {
		return fmt.Errorf("invalid authentication material")
	}
	if json.Unmarshal(plain, value) != nil {
		return fmt.Errorf("invalid authentication material")
	}
	return nil
}
func randomKey() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
