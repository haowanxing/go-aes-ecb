# go-aes-ecb

A Simple Go Encrypter/Decryper For AES-ECB Mode

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

	crypted := ecb.AesEncrypt(content, key)
	fmt.Println("crypted: ", crypted, string(crypted))

	origin := ecb.AesDecrypt(string(crypted), key)
	fmt.Println("decrypted: ", origin, string(origin))
}
```
