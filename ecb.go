/*
 * A Simple Tool: Encryptor/Decryptor of AES-ECB Mode With PKCS7
 * 简单封装的AES-ECB模式的加解密工具，采用PKCS7填充方式
 * Author: Haowanxing
 */

package ecb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// Aes/ECB模式的加密方法，PKCS7填充方式
func AesEncrypt(src, key string) []byte {
	Block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	if src == "" {
		panic("plaintext empty")
	}
	mode := NewECBEncrypter(Block)
	ciphertext := []byte(src)
	ciphertext = PKCS7Padding(ciphertext, mode.BlockSize())
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext
}

// Aes/ECB模式的解密方法，PKCS7填充方式
func AesDecrypt(src, key string) []byte {
	Block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	if src == "" {
		panic("plaintext empty")
	}
	mode := NewECBDecrypter(Block)
	ciphertext := []byte(src)
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS7UnPadding(ciphertext)
	return ciphertext
}

// ECB模式结构体
type ecb struct {
	b         cipher.Block
	blockSize int
}

// 实例化ECB对象
func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

// ECB加密类
type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		dst = dst[x.blockSize:]
		src = src[x.blockSize:]
	}
}

// ECB解密类
type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		dst = dst[x.blockSize:]
		src = src[x.blockSize:]
	}
}

// PKCS7填充
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7去除
func PKCS7UnPadding(ciphertext []byte) []byte {
	length := len(ciphertext)
	unpadding := int(ciphertext[length-1])
	return ciphertext[:(length - unpadding)]
}
