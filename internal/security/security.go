// Package security provê tokens, slugs, HMAC e criptografia AES-GCM.
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// RandomBytes retorna n bytes aleatórios.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RandomHex retorna uma string hex com n bytes de entropia.
func RandomHex(n int) string {
	return hex.EncodeToString(RandomBytes(n))
}

// Base62 retorna um código curto e fácil de digitar.
func Base62(n int) string {
	raw := RandomBytes(n)
	var sb strings.Builder
	for _, b := range raw {
		sb.WriteByte(base62Alphabet[int(b)%len(base62Alphabet)])
	}
	return sb.String()
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify transforma um nome em slug URL-amigável. "Teste PIX!" -> "teste-pix".
func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}

// HMACSign256 assina payload com HMAC-SHA256 usando um segredo, formatado como hex.
func HMACSign256(secret, payload []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(payload)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// HMACVerify valida uma assinatura no formato sha256=hex.
func HMACVerify(secret, payload []byte, signature string) bool {
	if !strings.HasPrefix(strings.ToLower(signature), "sha256=") {
		return false
	}
	want := strings.TrimPrefix(strings.ToLower(signature), "sha256=")
	got := strings.TrimPrefix(HMACSign256(secret, payload), "sha256=")
	return hmac.Equal([]byte(want), []byte(got))
}

// deriveKey deriva uma chave de 32 bytes a partir de uma senha livre.
func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// EncryptAES cifra texto plano com AES-GCM. Retorna base64(nonce||ct).
func EncryptAES(secret, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(deriveKey(string(secret)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := RandomBytes(gcm.NonceSize())
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptAES decifra base64(nonce||ct) gerado por EncryptAES.
func DecryptAES(secret []byte, b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKey(string(secret)))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext curto")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
