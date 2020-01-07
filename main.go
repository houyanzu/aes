package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
)

// GetAESCiphertext
func GetAESCiphertext(cleartext, password, fileName string) {
	mipri := EncryptAES([]byte(cleartext), []byte(password))
	//
	err := ioutil.WriteFile(fileName, mipri, 0644)
	if err != nil {
		panic(err)
	}
}

func padding(src []byte, blocksize int) []byte {
	padnum := blocksize - len(src)%blocksize
	pad := bytes.Repeat([]byte{byte(padnum)}, padnum)
	return append(src, pad...)
}

func unpadding(src []byte) []byte {
	n := len(src)
	unpadnum := int(src[n-1])
	return src[:n-unpadnum]
}

// EncryptAES .
func EncryptAES(src []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	src = padding(src, block.BlockSize())
	blockmode := cipher.NewCBCEncrypter(block, key)
	blockmode.CryptBlocks(src, src)
	return src
}

// DecryptAES .
func DecryptAES(src []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockmode := cipher.NewCBCDecrypter(block, key)
	blockmode.CryptBlocks(src, src)
	src = unpadding(src)
	return src
}
