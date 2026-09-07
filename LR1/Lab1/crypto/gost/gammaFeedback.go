package crypto

import "crypto/rand"

func pad(data []byte) []byte {
	padLen := 8 - (len(data) % 8)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

func unpad(data []byte) []byte {
	padLen := int(data[len(data)-1])
	if padLen > 0 && padLen <= 8 {
		return data[:len(data)-padLen]
	}
	return data
}

func GammaWithFeedbackEncrypt(data, key []byte) ([]byte, []byte) {
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}

	padded := pad(data)
	cipherText := make([]byte, len(padded))
	prev := iv

	for i := 0; i < len(padded); i += 8 {
		gamma := Gamma(prev, key, 8)

		block := padded[i : i+8]
		for j := range block {
			cipherText[i+j] = block[j] ^ gamma[j]
		}

		prev = cipherText[i : i+8]
	}

	return cipherText, iv
}

func GammaWithFeedbackDecrypt(data, key, iv []byte) []byte {
	result := make([]byte, len(data))
	prev := iv

	for i := 0; i < len(data); i += 8 {
		gamma := Gamma(prev, key, 8)

		block := data[i : i+8]
		for j := range block {
			result[i+j] = block[j] ^ gamma[j]
		}

		prev = data[i : i+8]
	}

	return unpad(result)
}
