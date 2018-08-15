package ecb

import (
	"encoding/base64"
	"testing"
)

type encryptionTest struct {
	plaintext string //原始文本
	key       string //加密Key
	encrypted string //加密后的Base64结果字符串
}

var tests = []encryptionTest{
	{"hello", "0123456789abcdef", "Z0x+8454yr2c7JwSWCOmOQ=="},
	{"hello world", "0123456789abcdef", "gWm+1O9JqIdFWcWyANqt5w=="},
	{"this is a long plaintext just full of [47]byte", "0123456789abcdef", "wz1xzURMAtqs4+XRwt+WwPPQnJFPrhvvwKCLcG0uOU0m9kNYO3WtUXigVLKbPAlh"},
	{"this is a long plaintext just full of [47]byte", "here is a random key of 32 bytes", "8EgQ3BMV15kUVhaOpR76FDb6HheuBH6+wV+vfaM7SHVvQM0ntLZhD4Np2MMi04ST"},
}

func TestAesEncrypt(t *testing.T) {
	for _, pair := range tests {
		plaintext := PKCS7Padding([]byte(pair.plaintext), 16) //BlockSize为16
		encrypted,err := AesEncrypt(plaintext, []byte(pair.key))
		if err != nil {
			t.Error(err.Error())
		}
		str := base64.StdEncoding.EncodeToString(encrypted)
		if pair.encrypted != str {
			t.Error(
				"for: ", pair.plaintext,
				"expected: ", pair.encrypted,
				"got: ", str,
			)
		}
	}
}

func TestAesDecrypt(t *testing.T) {
	for _, pair := range tests {
		str, err := base64.StdEncoding.DecodeString(pair.encrypted)
		if err != nil {
			t.Error(
				"For: ", pair.encrypted,
				"base64Decode Err: ", err,
			)
		} else {
			dectypted,err := AesDecrypt(str, []byte(pair.key))
			if err != nil {
				t.Error(err.Error())
			}
			dectypted = PKCS7UnPadding(dectypted)
			if pair.plaintext != string(dectypted) {
				t.Error(
					"For: ", pair.encrypted,
					"Expected: ", pair.plaintext,
					"Got: ", dectypted,
				)
			}
		}
	}
}
