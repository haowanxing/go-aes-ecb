# Go-AES-ECB

[![Build Status](https://www.travis-ci.org/haowanxing/go-aes-ecb.svg?branch=master)](https://www.travis-ci.org/haowanxing/go-aes-ecb)

A Simple Go Encryptor/Decryptor For AES-ECB Mode. With PKCS5 & Zeros (Un)Padding.

# Usage

```Go
package main

import (
	"fmt"
	ecb "github.com/haowanxing/go-aes-ecb"
)

func main() {
	content := "hello"
	key := "0123456789abcdef"

	// 使用PKCS#7对原文进行填充，BlockSize为16字节
	ciphertext := ecb.PKCS7Padding([]byte(content), 16)

	crypted := ecb.AesEncrypt(ciphertext, []byte(key)) //ECB加密
	fmt.Println("crypted: ", crypted, string(crypted))

	origin := ecb.AesDecrypt(crypted, []byte(key)) // ECB解密
	// 使用PKCS#7对解密后的内容去除填充
	origin = ecb.PKCS7UnPadding(origin)
	fmt.Println("decrypted: ", origin, string(origin))
}
```

输出结果：
```
crypted:  [103 76 126 243 142 120 202 189 156 236 156 18 88 35 166 57] gL~?xʽ??X#?9
decrypted:  [104 101 108 108 111] hello
```
