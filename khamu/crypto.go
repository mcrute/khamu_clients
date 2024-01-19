package khamu

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"code.crute.us/mcrute/golib/crypto/pkcs7"
)

// Implementation of Crypto-JS AES encrypt/decrypt
// Rough idea from: https://github.com/brainfoolong/cryptojs-aes-php/blob/bdc1cc675995784d899f6288ce35987977bd8e5d/src/CryptoJsAes.php

func encrypt(plain, pass string) (string, error) {
	jd, err := json.Marshal(plain)
	if err != nil {
		return "", err
	}

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	dx := make([]byte, 0)
	salted := make([]byte, 0)

	for len(salted) < 48 {
		input := append(append(dx[:], []byte(pass)...), salt...)
		h := md5.Sum(input)
		dx = h[:]
		salted = append(salted, dx[:]...)
	}

	key := salted[:32]
	iv := salted[32:48]

	aesc, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := pkcs7.Pad([]byte(jd), aesc.BlockSize())
	crypter := cipher.NewCBCEncrypter(aesc, iv)
	out := make([]byte, len(plaintext))
	crypter.CryptBlocks(out, plaintext)

	jd, err = json.Marshal(map[string]string{
		"ct": base64.StdEncoding.EncodeToString(out),
		"iv": hex.EncodeToString(iv),
		"s":  hex.EncodeToString(salt),
	})
	if err != nil {
		return "", err
	}

	return string(jd), nil
}

func decrypt(j, pass string) (string, error) {
	jd := map[string]string{}
	if err := json.Unmarshal([]byte(j), &jd); err != nil {
		return "", err
	}

	salt, err := hex.DecodeString(jd["s"])
	if err != nil {
		return "", err
	}

	// No need to unpack the IV, it's entirely derived from the salt

	ciphertext, err := base64.StdEncoding.DecodeString(jd["ct"])
	if err != nil {
		return "", err
	}

	dx := make([]byte, 0)
	salted := make([]byte, 0)

	for len(salted) < 48 {
		input := append(append(dx[:], []byte(pass)...), salt...)
		h := md5.Sum(input)
		dx = h[:]
		salted = append(salted, dx[:]...)
	}

	key := salted[:32]
	iv := salted[32:48]

	aesc, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	crypter := cipher.NewCBCDecrypter(aesc, iv)
	out := make([]byte, len(ciphertext))
	crypter.CryptBlocks(out, ciphertext)

	up, err := pkcs7.Unpad(out)
	if err != nil {
		return "", err
	}

	var outString string
	if err := json.Unmarshal(up, &outString); err != nil {
		return "", err
	}

	return outString, nil
}
