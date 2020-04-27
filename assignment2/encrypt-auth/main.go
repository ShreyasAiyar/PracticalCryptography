package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"os"
)

func padBytes(bytestream []byte, length int, value int) []byte {

	size := len(bytestream)
	requiredSize := length - size

	if requiredSize <= 0 {
		return bytestream
	}

	temp := make([]byte, requiredSize)
	for i := range temp {
		temp[i] = byte(value)
	}

	bytestream = append(bytestream, temp...)
	return bytestream
}

func generateBytes(length int, value int) []byte {

	temp := make([]byte, length)
	for i := range temp {
		temp[i] = byte(value)
	}
	return temp
}

func hmacSHA256(kMac []byte, M []byte) []byte {

	kMac = padBytes(kMac, 64, 0)
	outerKey := generateBytes(64, 92)
	innerKey := generateBytes(64, 54)

	outerKeyPad := make([]byte, 64)
	innerKeyPad := make([]byte, 64)

	for i := 0; i < 64; i++ {
		outerKeyPad[i] = outerKey[i] ^ kMac[i]
		innerKeyPad[i] = innerKey[i] ^ kMac[i]
	}

	hash := sha256.New()
	innerKeyPad = append(innerKeyPad, M...)
	hash.Write(innerKeyPad)
	innerHash := hash.Sum(nil)

	hash = sha256.New()
	outerKeyPad = append(innerKeyPad, innerHash...)
	hash.Write(outerKeyPad)

	return hash.Sum(nil)
}

func generatePaddingString(M []byte) []byte {

	n := int(math.Mod(float64(len(M)), 16))
	value := 0
	length := 16
	if n != 0 {
		length = 16 - n
		value = 16 - n
	} else {
		length = 16
		value = 16
	}

	ps := make([]byte, length)
	for i := range ps {
		ps[i] = byte(value)
	}
	return ps
}

func aesCBCEncrypt(kEnc []byte, M2 []byte) ([]byte, []byte) {

	IV := make([]byte, 16)
	rand.Read(IV)
	C := make([]byte, 0)

	var temp = make([]byte, 16)
	copy(temp, IV)
	for i := 0; i < len(M2); i += 16 {

		plaintext := M2[i : i+16]
		for j := 0; j < 16; j++ {
			temp[j] = temp[j] ^ plaintext[j]
		}

		block, err := aes.NewCipher(kEnc)
		check(err)
		ciphertext := make([]byte, 16)
		block.Encrypt(ciphertext, temp)
		temp = ciphertext
		C = append(C, ciphertext...)
	}
	return C, IV
}

func aesCBCDecrypt(kEnc []byte, C []byte, IV []byte) []byte {

	temp := IV
	M := make([]byte, 0)

	for i := 0; i < len(C); i += 16 {

		ciphertext := C[i : i+16]

		block, err := aes.NewCipher(kEnc)
		check(err)
		plaintext := make([]byte, 16)
		block.Decrypt(plaintext, ciphertext)

		for j := 0; j < 16; j++ {
			plaintext[j] = plaintext[j] ^ temp[j]
		}
		M = append(M, plaintext...)
		temp = ciphertext
	}
	return M
}

func encrypt(kEnc []byte, kMac []byte, M []byte) []byte {

	// Apply HMAC-SHA256
	var T = hmacSHA256(kMac, M)

	// Compute M′ = M||T
	var M1 = append(M, T...)

	// M′′ = M′||PS
	var PS = generatePaddingString(M)
	var M2 = append(M1, PS...)

	// C′ = AES-CBC-ENC(kenc, IV, M′′)
	C1, IV := aesCBCEncrypt(kEnc, M2)
	// C = (IV ||C′).
	var C = append(IV, C1...)

	return C
}

func decrypt(kEnc []byte, kMac []byte, C []byte) []byte {

	// Parse C = (IV ||C′)
	var IV = C[0:16]
	C = C[16:]
	// M′′ = AES-CBC-DEC(kenc, IV, C′)
	var M2 = aesCBCDecrypt(kEnc, C, IV)

	// Validate the message padding
	lastByte := int(M2[len(M2)-1])
	if lastByte > len(M2) || lastByte == 0 {
		fmt.Print("INVALID PADDING")
		return nil
	}
	for i := len(M2) - lastByte; i < len(M2); i++ {
		if int(M2[i]) != lastByte {
			fmt.Print("INVALID PADDING")
			return nil
		}
	}
	var M1 = M2[0 : len(M2)-lastByte]
	// Parse M′ as M||T
	if len(M1) < 32 {
		fmt.Print("INVALID MAC")
		return nil
	}
	var M = M1[0 : len(M1)-32]
	var T = M1[len(M1)-32:]

	// Apply the HMAC-SHA256 algorithm
	var T1 = hmacSHA256(kMac, M)

	if bytes.Compare(T1, T) != 0 {
		fmt.Print("INVALID MAC")
		return nil
	}
	return M
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	var mode = os.Args[1]
	var hexaKey = os.Args[2]
	var inputFile = os.Args[3]
	var outputFile = os.Args[4]

	var kEnc = make([]byte, 16)
	var kMac = make([]byte, 16)

	var key, error = hex.DecodeString(hexaKey)
	check(error)

	if len(key) == 32 {
		kEnc = key[0:16]
		kMac = key[16:32]
	} else if len(key) == 16 {
		kEnc = key[0:16]
	} else {
		return
	}

	// Read Input File
	text, err := ioutil.ReadFile(inputFile)
	check(err)

	// Read mode
	var result []byte
	if mode == "encrypt" {
		result = encrypt(kEnc, kMac, text)
	} else {
		result = decrypt(kEnc, kMac, text)
	}

	// Write to output File
	f, err := os.Create(outputFile)
	check(err)
	f.Write(result)
	f.Close()
}
