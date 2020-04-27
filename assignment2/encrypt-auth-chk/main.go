package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func aesCTREncrypt(kEnc []byte, M []byte) ([]byte, []byte) {

	// Create a 16 byte random nonce
	nonce := make([]byte, 16)
	rand.Read(nonce)

	// Create Ciphertext
	C := make([]byte, 0)

	// Main copy to return
	ctr := make([]byte, 16)
	copy(ctr, nonce)

	// intermediate is the enciphered IV
	intermediate := make([]byte, 16)

	block, err := aes.NewCipher(kEnc)
	check(err)
	block.Encrypt(intermediate, ctr)

	j := 0

	for i := 0; i < len(M); i++ {

		plaintext := M[i]
		ciphertext := make([]byte, 1)

		ciphertext[0] = intermediate[j] ^ plaintext

		C = append(C, ciphertext...)

		j++

		if j%16 == 0 {
			ctr[15] += byte(1)
			block, err := aes.NewCipher(kEnc)
			check(err)
			block.Encrypt(intermediate, ctr)
			j = 0
		}

	}
	return C, nonce
}

func aesCTRDecrypt(kEnc []byte, C []byte, nonce []byte) []byte {

	M := make([]byte, 0)

	// intermediate is the enciphered IV
	intermediate := make([]byte, 16)

	block, err := aes.NewCipher(kEnc)
	check(err)
	block.Encrypt(intermediate, nonce)

	j := 0

	for i := 0; i < len(C); i++ {

		ciphertext := C[i]
		plaintext := make([]byte, 1)

		block, err := aes.NewCipher(kEnc)
		check(err)
		block.Encrypt(intermediate, nonce)

		plaintext[0] = intermediate[j] ^ ciphertext

		M = append(M, plaintext...)

		j++

		if j%16 == 0 {
			nonce[15] += byte(1)
			block, err := aes.NewCipher(kEnc)
			check(err)
			block.Encrypt(intermediate, nonce)
			j = 0
		}
	}

	return M
}

func encrypt(kEnc []byte, M []byte) []byte {

	// Apply Checksum
	var chksum = 0
	for i := 0; i < len(M); i++ {
		chksum += int(M[i])
	}

	// Calculate Mod
	chksum = chksum % 256

	temp := make([]byte, 1)
	temp[0] = byte(chksum)

	// Compute M′ = Checksum||M
	M1 := append(temp, M...)

	// C′ = AES-CBC-ENC(kenc, IV, M′′)
	C1, IV := aesCTREncrypt(kEnc, M1)

	// C = (IV ||C′).
	C := append(IV, C1...)

	return C
}

func decrypt(kEnc []byte, C []byte) []byte {

	// Parse C = (IV ||C′)
	IV := make([]byte, 16)
	copy(IV, C[0:16])
	C = C[16:]

	// M′′ = AES-CBC-DEC(kenc, IV, C′)
	var M1 = aesCTRDecrypt(kEnc, C, IV)

	// Validate the Checksum
	chksum := M1[0]
	temp := 0

	for i := 1; i < len(M1); i++ {
		temp += int(M1[i])
	}
	temp = temp % 256

	if byte(temp) != chksum {
		fmt.Print("INVALID CHECKSUM")
		return nil
	}
	M := M1[1:]

	return M
}

func main() {

	var mode = os.Args[1]
	var key = os.Args[2]
	var inputFile = os.Args[3]
	var outputFile = os.Args[4]

	// Read Key
	kEnc, err := hex.DecodeString(key)
	check(err)

	// Read Input File
	text, err := ioutil.ReadFile(inputFile)
	check(err)

	// Read mode
	var result []byte
	if mode == "encrypt" {
		result = encrypt(kEnc, text)
	} else {
		result = decrypt(kEnc, text)
	}

	// Write to output File
	f, err := os.Create(outputFile)
	check(err)
	f.Write(result)
	f.Close()
}
